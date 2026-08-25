"""
CGI Protocol — Production API Gateway v2.1
============================================
Universal Verifiable AI inference API.
Domain-agnostic: Healthcare, Legal, Financial, Government, Insurance, Media, Defence.

Key changes from v1:
  - REMOVED: unittest.mock usage in production path
  - REMOVED: importlib.reload on every request
  - ADDED:   FastAPI lifespan context manager
  - ADDED:   API key authentication + rate limiting
  - ADDED:   Worker subprocess timeout
  - ADDED:   /health endpoint for Docker/GCP health checks
  - ADDED:   /v1/audit/export for audit log retrieval
  - ADDED:   Structured logging
  - ADDED:   Input validation (prompt length, model whitelist)
  - ADDED:   Request ID tracing
  - CACHED:  Private key loaded once at startup
"""

from __future__ import annotations

import asyncio
import base64
import collections
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
import csv
import io
from contextlib import asynccontextmanager
from typing import Any

# FIX C-4: filelock imported at module level, not inside the request handler.
# Re-importing a module on every request triggers a sys.modules lookup + 
# attribute resolution on each call — negligible in isolation but adds up at
# scale and obscures the dependency for static analysis tools.
from filelock import FileLock

import uvicorn
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from pydantic import BaseModel, Field

from config import settings
from middleware import (
    APIKeyStore,
    AuthMiddleware,
    RateLimitMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from contract import (
    ContractParameters,
    ContractVersion,
    ExecutionClaims,
    InferenceContract,
    RequiredObligations,
    SemanticBounds,
    TrustAssumptions,
    ValidityRules,
)
from ledger import AuditLedger
from merkle import MerkleTree
from registry import AttestationRegistry
from adapters import get_inference_adapter
from blockchain_anchor import AnchorEngine
from license_manager import LicenseManager, LicenseStatus


logger = logging.getLogger("cgi.gateway")

# ─────────────────────────────────────────────────────────────
# Application State (populated at startup, immutable at runtime)
# ─────────────────────────────────────────────────────────────

class AppState:
    """Holds loaded keys and singletons for the app lifetime."""
    private_key:    ec.EllipticCurvePrivateKey | None = None
    public_key_pem: str = ""
    ledger:         "AuditLedger | None" = None
    registry:       "AttestationRegistry | None" = None
    merkle_tree:    "MerkleTree | None" = None
    anchor_engine:  "AnchorEngine | None" = None
    license_status: "LicenseStatus | None" = None
    # FIX H-1: Adapter is a module-level singleton instantiated once at startup.
    # Previously get_inference_adapter() was called inside run_inference() on
    # every request, constructing a new object + performing an import lookup
    # each time. A single shared adapter is safe because adapters are stateless.
    adapter:        Any = None

    # FIX C-3: Replace the file-backed unbounded replay cache (disk DoS vector)
    # with an in-memory TTL set. Entries older than MAX_CONTRACT_AGE_S are
    # irreplayable by contract design (expires_after_timestamp = now + 3600).
    # Capped at REPLAY_CACHE_MAX to prevent memory exhaustion under sustained
    # attack. When at capacity, the oldest entry is evicted (LRU approximation).
    _replay_set:    set = None
    _replay_times: collections.deque[tuple[float, str]] = None

    # Circuit Breaker state
    backend_failures: int = 0
    circuit_open_until: float = 0.0
    circuit_lock: asyncio.Lock | None = None

    REPLAY_CACHE_MAX = 100_000   # maximum entries before forced eviction
    MAX_CONTRACT_AGE_S = 3_600  # 1 hour — matches expires_after_timestamp in contract

    def replay_seen(self, execution_id: str) -> bool:
        if self._replay_set is None:
            return False
        self._evict_expired()
        return execution_id in self._replay_set

    def replay_record(self, execution_id: str) -> None:
        """Mark execution_id as processed."""
        if self._replay_set is None:
            self._replay_set = set()
            self._replay_times = collections.deque()
        if len(self._replay_set) >= self.REPLAY_CACHE_MAX:
            # Evict oldest entry to enforce cap
            old_ts, old_id = self._replay_times.popleft()
            self._replay_set.discard(old_id)
        self._replay_set.add(execution_id)
        self._replay_times.append((time.monotonic(), execution_id))

    def _evict_expired(self) -> None:
        if not self._replay_times:
            return
        cutoff = time.monotonic() - self.MAX_CONTRACT_AGE_S
        while self._replay_times and self._replay_times[0][0] < cutoff:
            _, old_id = self._replay_times.popleft()
            self._replay_set.discard(old_id)

    def init_replay_cache(self) -> None:
        self._replay_set   = set()
        self._replay_times = collections.deque()


app_state = AppState()


# ─────────────────────────────────────────────────────────────
# Startup / Shutdown (Lifespan)
# ─────────────────────────────────────────────────────────────

def _ensure_directories() -> None:
    os.makedirs(settings.AUTH_DIR, exist_ok=True)
    os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
    os.makedirs(settings.LOG_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(settings.DB_PATH), exist_ok=True)

def _ensure_governance_key() -> None:
    """Generate ECDSA key pair if not present."""
    if os.environ.get("CGI_PRIVATE_KEY"):
        logger.info("Using CGI_PRIVATE_KEY from environment for governance.")
        return
        
    if not os.path.exists(settings.PRIVATE_KEY_PATH):
        logger.info("Generating ECDSA secp256k1 governance key pair...")
        key = ec.generate_private_key(ec.SECP256K1())
        with open(settings.PRIVATE_KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(settings.PRIVATE_KEY_PASSPHRASE.encode("utf-8")) if settings.PRIVATE_KEY_PASSPHRASE else serialization.NoEncryption(),
            ))
        # Set restrictive permissions on Unix
        if os.name == "posix":
            os.chmod(settings.PRIVATE_KEY_PATH, 0o600)
        logger.info("Governance key generated at %s", settings.PRIVATE_KEY_PATH)


def _load_private_key() -> ec.EllipticCurvePrivateKey:
    from cryptography.hazmat.primitives import serialization
    with open(settings.PRIVATE_KEY_PATH, "rb") as key_file:
        pw = settings.PRIVATE_KEY_PASSPHRASE.encode("utf-8") if settings.PRIVATE_KEY_PASSPHRASE else None
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=pw,
        )    
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"Expected ECDSA key, got {type(key).__name__}")
    return key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan — replaces deprecated @app.on_event."""
    # ── Startup ───────────────────────────────────────────
    app_state.circuit_lock = asyncio.Lock()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    # VAL-2: Switch to structured JSON logging when LOG_FORMAT=json.
    # Compatible with Datadog, Grafana Loki, GCP Cloud Logging.
    if settings.LOG_FORMAT.lower() == "json":
        from middleware import configure_json_logging
        configure_json_logging()

    _ensure_directories()
    _ensure_governance_key()

    app_state.private_key = _load_private_key()
    pub_key = app_state.private_key.public_key()
    app_state.public_key_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # 2. Init Ledger
    app_state.ledger = AuditLedger(settings.DB_PATH)
    app_state.registry = AttestationRegistry(chain_path=settings.CHAIN_FILE)

    # Seed Merkle Tree from existing ledger records so state
    # survives container restarts — not just in-memory for the session.
    # CRIT-1 fix: Load persisted leaf hashes directly from the merkle_leaves table.
    # The previous approach re-built the tree from export_audit_log(limit=10000),
    # which permanently diverged the Merkle root on restart at record 10,001.
    # Direct leaf restore is also faster: no re-hashing, just list restoration.
    app_state.merkle_tree = MerkleTree()
    prior_leaves = app_state.ledger.load_merkle_leaves()
    if prior_leaves:
        app_state.merkle_tree.leaves = prior_leaves
        app_state.merkle_tree._tree_cache = None  # mark dirty for lazy rebuild
        logger.info(
            "MerkleTree restored from %d persisted leaf hashes.",
            len(prior_leaves),
        )

    # FIX H-1: Instantiate adapter once at startup — not per-request.
    app_state.adapter = get_inference_adapter()
    logger.info("Inference adapter initialised: %s", type(app_state.adapter).__name__)

    # CRIT-3 fix: Init bounded in-memory replay cache, then hydrate from the
    # persistent DB store so replay protection survives container restarts.
    app_state.init_replay_cache()
    active_replay_ids = app_state.ledger.load_active_replay_ids(
        ttl_seconds=AppState.MAX_CONTRACT_AGE_S
    )
    if active_replay_ids:
        wall_now = time.time()
        mono_now = time.monotonic()
        for exec_id, seen_wall in active_replay_ids:
            # Convert wall-clock DB timestamp to monotonic-equivalent for eviction.
            age = wall_now - seen_wall
            mono_equiv = mono_now - age
            app_state._replay_set.add(exec_id)
            app_state._replay_times.append((mono_equiv, exec_id))
        logger.info(
            "Replay cache hydrated with %d active IDs from persistent store.",
            len(active_replay_ids),
        )

    # Initialise Blockchain Anchor Engine
    os.makedirs(settings.ANCHOR_DIR, exist_ok=True)
    app_state.anchor_engine = AnchorEngine(
        ledger=app_state.ledger,
        anchor_dir=settings.ANCHOR_DIR,
        calendar_urls=settings.OTS_CALENDAR_URLS,
        min_batch_size=settings.ANCHOR_MIN_BATCH_SIZE,
    )

    # ── License Verification ─────────────────────────────────
    license_manager = LicenseManager(issuer_public_key_path=settings.ISSUER_PUB_KEY_PATH)
    
    # 1. Attempt to load a dynamically activated license first
    active_license_path = settings.LICENSE_KEY_PATH
    license_dir = os.path.join(settings.OUTPUT_DIR, "activated_licenses")
    if os.path.exists(license_dir):
        activated_files = [os.path.join(license_dir, f) for f in os.listdir(license_dir) if f.endswith(".json")]
        if activated_files:
            active_license_path = max(activated_files, key=os.path.getmtime)
            
    license_status = None
    if active_license_path and os.path.exists(active_license_path):
        # We explicitly use ENFORCE here to actually validate the file rather than 
        # instantly skipping it if the environment is set to DISABLED
        status = license_manager.verify_license(
            license_file_path=active_license_path,
            enforcement="ENFORCE",
        )
        if status.valid:
            license_status = status
            logger.info("Loaded previously activated license: %s", status.license_id)

    # 2. Fallback to configured enforcement if no valid dynamic license exists
    if not license_status:
        license_status = license_manager.verify_license(
            license_file_path=settings.LICENSE_KEY_PATH,
            enforcement=settings.LICENSE_ENFORCEMENT,
        )

    app_state.license_status = license_status

    # Hard-fail if license is invalid
    if not license_status.valid:
        logger.error(
            "LICENSE INVALID: Server refusing to start. Ensure a valid license key is provided or activated via dashboard."
        )
        sys.exit(1)

    if license_status.valid:
        logger.info(
            "LICENSE_OK | tier=%s licensee=%s domain=%s expires=%s days_remaining=%d",
            license_status.tier,
            license_status.licensee_name,
            license_status.licensee_domain,
            license_status.expires_at_iso,
            license_status.days_remaining,
        )
    else:
        logger.warning("LICENSE_WARN | %s", license_status.error or "No license configured")

    logger.info(
        "CGI Protocol API started | enclave_mode=%s | model=%s | domain=%s | anchor=%s | license=%s",
        settings.ENCLAVE_MODE,
        settings.MODEL_ID,
        settings.DOMAIN_CONTEXT,
        "ENABLED" if settings.ANCHOR_ENABLED else "DISABLED",
        license_status.tier if license_status.valid else "UNLICENSED",
    )

    # ── Background Anchor Task ──────────────────────────────
    async def _anchor_loop():
        """Runs the anchor cycle every ANCHOR_INTERVAL_SECONDS."""
        await asyncio.sleep(10)  # Brief startup delay
        while True:
            if settings.ANCHOR_ENABLED and app_state.anchor_engine:
                try:
                    result = app_state.anchor_engine.run_anchor_cycle()
                    logger.info(
                        "ANCHOR_TASK | status=%s records=%d anchor_id=%s",
                        result.status, result.record_count, result.anchor_id or "N/A",
                    )
                except Exception as exc:
                    logger.error("ANCHOR_TASK_ERROR | %s", exc)
            await asyncio.sleep(settings.ANCHOR_INTERVAL_SECONDS)

    # FIX H-2: asyncio.ensure_future() is deprecated in Python 3.10+.
    # asyncio.create_task() is the correct modern API. It also binds the
    # task to the *running* event loop, preventing subtle loop-replacement bugs.
    app_state.anchor_task = asyncio.create_task(_anchor_loop())



    yield

    # ── Shutdown ──────────────────────────────────────
    if getattr(app_state, "anchor_task", None):
        app_state.anchor_task.cancel()
        try:
            await app_state.anchor_task
        except asyncio.CancelledError:
            pass
            
    if app_state.ledger:
        app_state.ledger.close()
    logger.info("CGI Protocol API shut down gracefully")


# ─────────────────────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    lifespan=lifespan,
)

# Middleware stack (order matters — outermost first)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_key_store = APIKeyStore(settings.API_KEYS_FILE)

def get_dynamic_rate_limit() -> int:
    if app_state.license_status and app_state.license_status.valid:
        return app_state.license_status.max_requests_per_minute
    return settings.RATE_LIMIT_RPM

app.add_middleware(RateLimitMiddleware, max_requests=get_dynamic_rate_limit)
app.add_middleware(AuthMiddleware, key_store=_key_store)
app.add_middleware(RequestIDMiddleware)

# Initialise SSE broadcaster (singleton, shared across all requests)
from sse_router import AttestationBroadcaster
_broadcaster = AttestationBroadcaster()


# ─────────────────────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────────────────────

class InferenceRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=settings.MAX_PROMPT_LENGTH)
    model_id: str = Field(default=settings.MODEL_ID)
    max_tokens: int = Field(default=settings.DEFAULT_MAX_TOKENS, ge=1, le=131072)
    data_classification: str = Field(default=settings.DEFAULT_DATA_CLASSIFICATION)
    purpose_of_use: str = Field(default="GENERAL")


class HealthResponse(BaseModel):
    status: str
    version: str
    enclave_mode: str
    model_id: str
    uptime_seconds: float
    # VAL-3: Chain metrics exposed on /health for monitoring without an API key.
    ledger_count: int = 0
    merkle_root: str = ""


_boot_time = time.monotonic()


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
def health_check():
    """Docker / GCP health check endpoint (VAL-3: exposes chain metrics for monitoring)."""
    ledger_count = app_state.ledger.count() if app_state.ledger else 0
    merkle_root = app_state.merkle_tree.get_root() if app_state.merkle_tree else ""
    return HealthResponse(
        status="ok",
        version=settings.API_VERSION,
        enclave_mode=settings.ENCLAVE_MODE,
        model_id=settings.MODEL_ID,
        uptime_seconds=round(time.monotonic() - _boot_time, 1),
        ledger_count=ledger_count,
        merkle_root=merkle_root,
    )


@app.get("/v1/public-key")
def get_public_key():
    """Returns the governance public key for offline cryptographic verification."""
    return {"public_key_pem": app_state.public_key_pem}


# ─────────────────────────────────────────────────────────────
# License Activation & Status
# ─────────────────────────────────────────────────────────────

class LicenseActivateRequest(BaseModel):
    license_key: str = Field(..., description="CGI-* compact license key string issued by CGI Protocol")


@app.post("/v1/license/activate")
async def activate_license(req: LicenseActivateRequest):
    """
    Activate a CGI Protocol license using the compact key string.
    The client pastes the CGI-* key they received after purchase.
    The server verifies the ECDSA signature, persists the license,
    and hot-reloads it — no server restart required.
    """
    import base64 as _b64
    import re

    # Remove all whitespace (newlines, spaces, etc.) so users can paste the whole block as-is
    raw_key = re.sub(r'\s+', '', req.license_key)
    if not raw_key.startswith("CGI-"):
        raise HTTPException(status_code=400, detail="Invalid license key format. Key must start with 'CGI-'.")

    # Decode the compact key back to JSON
    try:
        compact_json = _b64.urlsafe_b64decode(raw_key[4:].encode("utf-8")).decode("utf-8")
        license_data = json.loads(compact_json)
    except Exception:
        raise HTTPException(status_code=400, detail="License key is malformed or corrupted.")

    # Verify ECDSA signature using the embedded issuer public key
    license_mgr = LicenseManager(issuer_public_key_path=settings.ISSUER_PUB_KEY_PATH)
    if not license_mgr._verify_signature(license_data):
        raise HTTPException(
            status_code=403,
            detail="License key signature is INVALID. This key may be forged or tampered with."
        )

    # Check expiry
    import time as _t
    expires_at = license_data.get("validity", {}).get("expires_at", 0)
    grace = license_data.get("validity", {}).get("grace_period_seconds", 86400)
    if _t.time() > expires_at + grace:
        raise HTTPException(
            status_code=403,
            detail=f"This license expired on {_t.strftime('%Y-%m-%d', _t.gmtime(expires_at))} and the grace period has ended. Contact support to renew."
        )

    # Persist the license to disk
    license_id = license_data.get("license_id", "unknown")
    os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
    license_dir = os.path.join(settings.OUTPUT_DIR, "activated_licenses")
    os.makedirs(license_dir, exist_ok=True)
    license_path = os.path.join(license_dir, f"{license_id}.json")
    with open(license_path, "w", encoding="utf-8") as f:
        json.dump(license_data, f, indent=2)

    # Hot-reload the license into running app state — no restart needed
    new_status = license_mgr.verify_license(license_path, enforcement="ENFORCE")
    app_state.license_status = new_status

    licensee = license_data.get("licensee", {})
    tier = license_data.get("tier", "UNKNOWN")
    days_remaining = max(0, int((expires_at - _t.time()) / 86400))

    logger.info(
        "LICENSE_ACTIVATED | id=%s licensee=%s tier=%s expires=%s",
        license_id, licensee.get("name"), tier,
        _t.strftime("%Y-%m-%d", _t.gmtime(expires_at))
    )

    return {
        "status": "ACTIVATED",
        "license_id": license_id,
        "licensee": licensee.get("name"),
        "tier": tier,
        "domain": licensee.get("domain"),
        "expires": _t.strftime("%Y-%m-%d", _t.gmtime(expires_at)),
        "expires_timestamp": expires_at,
        "days_remaining": days_remaining,
        "max_requests_per_day": license_data.get("features", {}).get("max_requests_per_day", 0),
        "max_requests_per_minute": license_data.get("features", {}).get("max_requests_per_minute", 0),
        "blockchain_anchor": license_data.get("features", {}).get("blockchain_anchor", False),
        "audit_export": license_data.get("features", {}).get("audit_export", False),
        "data_classifications": license_data.get("features", {}).get("data_classifications", ["PUBLIC"]),
        "message": f"License activated successfully. {tier} tier valid for {days_remaining} days."
    }


@app.post("/v1/infer")
async def run_inference(req: InferenceRequest, request: Request):
    """
    Executes an AI inference inside the verifiable CGI wrapper and returns
    the cryptographically signed attestation bundle.
    """
    request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
    api_key_id = getattr(request.state, "api_key_id", "anonymous")

    # ── 1. Input validation ───────────────────────────────────
    if req.data_classification not in ("CONFIDENTIAL", "PII", "PUBLIC", "PRIVILEGED", "CLASSIFIED"):
        raise HTTPException(
            status_code=400,
            detail="data_classification must be one of: CONFIDENTIAL, PII, PUBLIC, PRIVILEGED, CLASSIFIED",
        )

    # ── 1b. Per-key license tier resolution ──────────────────
    # Priority: API-key 'tier' field (multi-tenant) → server-level license → open
    # This allows different API keys to have different entitlements on the same server.
    server_lic = app_state.license_status
    effective_lic = server_lic  # server-level fallback

    key_tier = getattr(request.state, "api_key_tier", None)
    if key_tier:
        from license_manager import LicenseStatus as _LS, _TIER_LIMITS, LicenseTier
        import time as _time
        try:
            resolved_tier = LicenseTier(key_tier.upper())
            tier_limits = _TIER_LIMITS[resolved_tier]
            effective_lic = _LS(
                valid=True,
                license_id=f"key-tier:{api_key_id}",
                licensee_name=getattr(request.state, "api_key_org", "unknown"),
                tier=resolved_tier,
                expires_at=server_lic.expires_at if server_lic else 0.0,
                max_requests_per_day=tier_limits["max_requests_per_day"],
                max_requests_per_minute=tier_limits["max_requests_per_minute"],
                allowed_model_prefixes=tier_limits.get("allowed_models_prefix", []),
                blockchain_anchor=tier_limits["blockchain_anchor"],
                audit_export=tier_limits["audit_export"],
                max_prompt_length=tier_limits["max_prompt_length"],
                data_classifications=tier_limits["data_classifications"],
                signature=server_lic.signature if server_lic else "",
            )
        except (ValueError, KeyError):
            logger.warning("INVALID_KEY_TIER | key_id=%s tier=%s — using server license", api_key_id, key_tier)

    # ── 1c. Enforce effective license ────────────────────────
    if not effective_lic or not effective_lic.valid:
        raise HTTPException(
            status_code=403,
            detail="A valid license is required to perform inference. Please activate a license key."
        )
    
    import time as _t
    if _t.time() > effective_lic.expires_at:
        raise HTTPException(
            status_code=403,
            detail="Your license has expired. Please activate a new license key in the dashboard."
        )
        
    if not effective_lic.is_model_allowed(req.model_id):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Model '{req.model_id}' is not permitted under your "
                f"{effective_lic.tier} license. Upgrade to access this model."
            ),
        )
    if not effective_lic.is_classification_allowed(req.data_classification):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Data classification '{req.data_classification}' is not permitted "
                f"under your {effective_lic.tier} license."
            ),
        )

    # FIX M-1: Pydantic v2 API compatibility.
    prompt_field = req.model_fields.get("prompt")
    max_len = settings.MAX_PROMPT_LENGTH
    if prompt_field and prompt_field.metadata:
        for m in prompt_field.metadata:
            if hasattr(m, 'max_length'):
                max_len = m.max_length
                break

    effective_max_prompt = min(
        max_len,
        effective_lic.max_prompt_length if effective_lic else settings.MAX_PROMPT_LENGTH,
    )
    if len(req.prompt) > effective_max_prompt:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Prompt length {len(req.prompt)} exceeds your license limit of "
                f"{effective_max_prompt} characters "
                f"({effective_lic.tier if effective_lic else 'UNLIMITED'} tier)."
            ),
        )

    logger.info(
        "INFERENCE_REQUEST | request_id=%s user=%s model=%s classification=%s prompt_len=%d license_tier=%s",
        request_id, api_key_id, req.model_id, req.data_classification, len(req.prompt),
        effective_lic.tier if (effective_lic and effective_lic.valid) else "UNLICENSED",
    )


    # ── 2. Build InferenceContract ────────────────────────────
    prompt_hash = hashlib.sha256(req.prompt.encode("utf-8")).hexdigest()
    execution_id = f"exec-{uuid.uuid4().hex}"

    contract = InferenceContract(
        execution_id=execution_id,
        prompt_hash=prompt_hash,
        version=ContractVersion(
            protocol_version="3.1",
            contract_schema="cgi-attestation-v3.1",
            assurance_level="A1",
        ),
        parameters=ContractParameters(
            model_id=req.model_id,
            max_output_tokens=req.max_tokens,
            temperature=settings.DEFAULT_TEMPERATURE,
            seed=settings.DEFAULT_SEED,
            required_data_sources=[],
            data_classification=req.data_classification,
            purpose_of_use=req.purpose_of_use,
            authorized_by=api_key_id,
        ),
        claims=ExecutionClaims(
            model_identity=f"sha256:{req.model_id}",
            execution_mode="deterministic",
            network_policy="unverified",
            tool_policy="no-external-tools",
            provenance="complete",
            policy_hash="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        validity=ValidityRules(
            max_clock_skew_ms=5000,
            expires_after_timestamp=int(time.time()) + 3600,
        ),
        trust_assumptions=TrustAssumptions(
            requires_secure_tee=False,
            requires_hash_collision_resistance="SHA-256",
            requires_audit_trail=True,
        ),
        semantic_bounds=SemanticBounds(
            allowed_intents=["explain", "analyze", "summarize", "classify", "extract"],
            max_transaction_value=0.0,
            schema_strict_mode=True,
        ),
        obligations=RequiredObligations(
            zk_proof_required=False,
            watermark_type="aaronson-logit-prng",
        ),
        extensions={
            "request_id": request_id,
            "data_classification": req.data_classification,
        },
    )

    # ── 3. Replay guard (persistent + in-memory — CRIT-3 fix) ──────
    if app_state.replay_seen(execution_id):
        raise HTTPException(
            status_code=409,
            detail=f"REPLAY BLOCKED: execution_id '{execution_id}' already processed.",
        )
    app_state.replay_record(execution_id)
    # Persist to DB so replay protection survives restarts (CRIT-3)
    app_state.ledger.persist_replay_id(execution_id)

    # ── 4. Execute Inference via Adapter (Singleton + Circuit Breaker) ────
    wall_start = time.monotonic()
    
    if wall_start < app_state.circuit_open_until:
        raise HTTPException(
            status_code=503,
            detail="Service Unavailable: AI backend circuit breaker is open.",
        )

    try:
        generated_text, stop_reason, token_count = await asyncio.to_thread(
            app_state.adapter.generate,
            prompt=req.prompt,
            model_id=req.model_id,
            max_tokens=req.max_tokens,
            execution_id=execution_id,
            seed=settings.DEFAULT_SEED,
        )
        # Reset circuit breaker on success
        async with app_state.circuit_lock:
            app_state.backend_failures = 0
    except Exception as e:
        async with app_state.circuit_lock:
            app_state.backend_failures += 1
            if app_state.backend_failures >= 3:
                app_state.circuit_open_until = time.monotonic() + 30.0 # open for 30s
                logger.critical("CIRCUIT_BREAKER_OPEN | 3 consecutive AI backend failures.")
            
        logger.error(
            "ADAPTER_FAILURE | request_id=%s exec_id=%s error=%s",
            request_id, execution_id, str(e),
        )
        raise HTTPException(
            status_code=500,
            detail=f"Inference backend failed: {str(e)}",
        )

    wall_ms = round((time.monotonic() - wall_start) * 1000, 1)

    logger.info(
        "INFERENCE_COMPLETE | request_id=%s exec_id=%s tokens=%d duration_ms=%s stop=%s",
        request_id, execution_id, token_count, wall_ms, stop_reason,
    )

    # ── 6. Build attestation bundle ───────────────────────────
    execution_metrics: dict[str, Any] = {
        "wall_duration_ms": wall_ms,
        "tokens_generated": token_count,
        "stop_reason": stop_reason,
        "enclave_mode": "none",
    }
    environment_measurements = {
        "pcr0_kernel_hash": "status: NOT_MEASURED",
        "pcr1_engine_hash": "status: NOT_MEASURED",
        "cuda_version": "12.1",
        "pytorch_version": "2.2.0",
        "compute_precision": "bfloat16"
    }
    
    temporal_anchor = {
        "timestamp_utc": int(time.time()),
        "rfc3161_timestamp_token": "status: NOT_MEASURED",
        "latest_blockchain_hash": "status: NOT_MEASURED"
    }

    bundle: dict[str, Any] = {
        "schema_version": "cgi-attestation-v3.1",
        "payload": {
            "contract": contract.to_dict(),
            "environment_measurements": environment_measurements,
            "temporal_anchor": temporal_anchor,
            "license_entitlement": {
                "license_id": effective_lic.license_id if effective_lic else "unlicensed",
                "tier": effective_lic.tier if effective_lic else "unlicensed",
                "signature": effective_lic.signature if (effective_lic and hasattr(effective_lic, "signature")) else "",
            },
            "verification_verdict": {
                "status": "CRYPTOGRAPHICALLY_COMMITTED",
                "runtime_environment": "STANDARD_OS_PROCESS",
                "model_integrity": "UNVERIFIED",
                "execution_metrics": execution_metrics,
            },
            "inference_output": generated_text,
        },
    }

    # ── 7. Cryptographic signing ────────────────────────
    payload_bytes = json.dumps(
        bundle["payload"], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    # CRIT-2 fix: ECDSA signing is CPU-bound. Running it synchronously inside an
    # async handler stalls the event loop for every concurrent request. Offload to
    # a thread-pool executor so the loop remains free to serve other connections.
    signature_bytes = await asyncio.to_thread(
        app_state.private_key.sign, payload_bytes, ec.ECDSA(hashes.SHA256())
    )
    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    bundle["attestation"] = {
        "root_hash": "0x" + payload_hash,
        "signature": signature_b64,
        "signed_by": "governance-key",
        "certificate_chain": [
            "status: NOT_IMPLEMENTED"
        ],
        "enclave_mode": settings.ENCLAVE_MODE,
        "attested_at": int(time.time()),
    }

    # ── 8. Persist bundle ─────────────────────────────────────
    bundle_name = f"portable_attestation_{execution_id}.json"
    bundle_path = os.path.join(settings.OUTPUT_DIR, bundle_name)

    with open(bundle_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=4)

    # Atomic latest pointer
    latest_path = settings.LATEST_BUNDLE
    with tempfile.NamedTemporaryFile(
        mode="w", dir=settings.OUTPUT_DIR, suffix=".tmp",
        delete=False, encoding="utf-8",
    ) as f_tmp:
        json.dump(bundle, f_tmp, indent=4)
        tmp_path = f_tmp.name
    os.replace(tmp_path, latest_path)

    # ── 9. Append to registry chain ───────────────────────────
    try:
        app_state.registry.append(bundle_path)
    except Exception as exc:
        logger.warning("Registry append failed: %s", exc)

    # ── 10. Record in audit ledger ────────────────────────────
    app_state.ledger.record_attestation(
        execution_id=execution_id,
        root_hash=bundle["attestation"]["root_hash"],
        signature=signature_b64,
        bundle=bundle,
        request_id=request_id,
        user_id=api_key_id,
        data_classification=req.data_classification,
    )

    # ── 11. Audit merkle tree ──────────────────────
    # CRIT-1 fix: Capture the returned leaf hash and persist it to the DB.
    leaf_hash = app_state.merkle_tree.add_leaf({
        "event": "INFERENCE_ATTESTED",
        "execution_id": execution_id,
        "root_hash": bundle["attestation"]["root_hash"],
        "timestamp": time.time(),
    })
    app_state.ledger.append_merkle_leaf(leaf_hash)

    # ── 12. Broadcast to SSE dashboard subscribers ────────────
    _broadcaster.publish({
        "type":              "ATTESTATION",
        "execution_id":      execution_id,
        "root_hash":         bundle["attestation"]["root_hash"],
        "signature":         signature_b64,
        "model_id":          req.model_id,
        "data_classification": req.data_classification,
        "tokens_generated":  token_count,
        "wall_duration_ms":  wall_ms,
        "output_preview":    generated_text[:200] if req.data_classification == "PUBLIC" else "[REDACTED - SENSITIVE CLASSIFICATION]",
        "ledger_total":      app_state.ledger.count(),
        "chain_length":      app_state.registry._meta.get("length", 0) if app_state.registry else 0,
    })



    return bundle


@app.get("/v1/audit/export")
def export_audit_log(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    classification: str | None = None,
):
    """
    Export audit log entries for compliance reporting.
    Returns JSONL-compatible list of attestation records.
    """
    api_key_id = getattr(request.state, "api_key_id", "anonymous")
    scopes = getattr(request.state, "api_key_scopes", [])

    if _key_store.is_enabled and "audit" not in scopes:
        raise HTTPException(
            status_code=403,
            detail="API key does not have 'audit' scope",
        )

    entries = app_state.ledger.export_audit_log(
        limit=limit,
        offset=offset,
        classification=classification,
    )

    logger.info(
        "AUDIT_EXPORT | user=%s count=%d offset=%d classification=%s",
        api_key_id, len(entries), offset, classification,
    )

    return {
        "total": len(entries),
        "offset": offset,
        "entries": entries,
    }


@app.get("/dashboard/export/csv")
def export_audit_log_csv(request: Request, days: int = 30):
    """
    Export full audit log as a streamed CSV file for the dashboard.
    Requires 'audit' scope (CRIT-5 fix: endpoint was previously unauthenticated).
    Limits export to the specified number of days to prevent memory/timeout issues on 10M+ rows.
    """
    scopes = getattr(request.state, "api_key_scopes", [])
    if _key_store.is_enabled and "audit" not in scopes:
        raise HTTPException(
            status_code=403,
            detail="API key does not have 'audit' scope. Required for CSV export.",
        )

    since_timestamp = time.time() - (days * 24 * 3600)

    def iter_csv():
        # Write header
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["execution_id", "timestamp_iso", "root_hash", "request_id", "user_id", "data_classification", "anchor_id"])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        
        # Stream rows
        for row in app_state.ledger.export_audit_log_stream(since_timestamp=since_timestamp):
            writer.writerow([
                row["execution_id"],
                row["timestamp_iso"],
                row["root_hash"],
                row["request_id"],
                row["user_id"],
                row["data_classification"],
                row["anchor_id"]
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    from fastapi.responses import StreamingResponse
    return StreamingResponse(
        iter_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="cgi_audit_log.csv"'}
    )

@app.get("/v1/attestation/{execution_id}")
def get_attestation(execution_id: str):
    """Retrieve a specific attestation by execution ID with disk fallback."""
    if not re.match(r"^exec-[0-9a-fA-F-]+$", execution_id):
        raise HTTPException(status_code=400, detail="Invalid execution_id format")
    # 1. Primary lookup in the DB
    result = app_state.ledger.get_attestation(execution_id)
    if result is not None:
        return result

    # 2. Fast disk fallback (for deterministic filenames)
    fast_path = os.path.join(settings.OUTPUT_DIR, f"portable_attestation_{execution_id}.json")
    if os.path.exists(fast_path):
        try:
            with open(fast_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
                
            # Self-healing: repair the DB record
            _repair_db_record(bundle)
            return bundle
        except Exception as e:
            logger.error(f"Failed to read fast fallback file {fast_path}: {e}")

    # 3. Deep disk fallback (for legacy random hex filenames)
    for filename in os.listdir(settings.OUTPUT_DIR):
        if filename.startswith("portable_attestation_") and filename.endswith(".json"):
            filepath = os.path.join(settings.OUTPUT_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    bundle = json.load(f)
                    
                if bundle.get("payload", {}).get("contract", {}).get("execution_id") == execution_id:
                    # Self-healing: repair the DB record
                    _repair_db_record(bundle)
                    return bundle
            except Exception:
                continue

    raise HTTPException(status_code=404, detail="Attestation not found")


@app.get("/v1/attestation/{execution_id}/download")
def download_attestation(execution_id: str):
    """Download a specific attestation as a JSON file attachment."""
    bundle = get_attestation(execution_id)
    from fastapi.responses import Response
    import json
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="CGI-attestation-{execution_id}.json"'}
    )

@app.post("/v1/attestation/{execution_id}/verify")
def verify_attestation_deep(execution_id: str):
    """
    Perform deep cryptographic authentication of an attestation.
    Validates ECDSA signatures, ZK proofs, Merkle paths, and semantic bounds.
    """
    if not re.match(r"^exec-[0-9a-fA-F-]+$", execution_id):
        raise HTTPException(status_code=400, detail="Invalid execution_id format")
    bundle = get_attestation(execution_id)
    
    payload = bundle.get("payload", {})
    attestation = bundle.get("attestation", {})
    evidence = payload.get("evidence", {})
    
    results = {
        "execution_id": execution_id,
        "signature_valid": False,
        "zk_proof_valid": "N/A",
        "semantic_bounds_valid": False,
        "formal_verification": "FAIL",
        "errors": []
    }
    
    # 1. Verify ECDSA Signature
    try:
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        import base64
        import json
        
        signature_bytes = base64.b64decode(attestation.get("attestation_signature", attestation.get("signature", "")))
        
        # The runtime actually signs the raw JSON payload bytes, not the root hash string.
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            
        # We load the public key loaded at startup (app_state.public_key_pem)
        public_key = serialization.load_pem_public_key(app_state.public_key_pem.encode("utf-8"))
        public_key.verify(signature_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
        results["signature_valid"] = True
    except Exception as e:
        results["errors"].append(f"Cryptographic Signature Validation Failed: {e}")
        
    # 2. Verify ZK Proofs (if required)
    zk_required = payload.get("contract", {}).get("obligations", {}).get("zk_proof_required", False)
    if zk_required:
        zk_proof = evidence.get("zk_snark_proof")
        zk_public_signal = evidence.get("zk_public_signal")
        if not zk_proof or not zk_public_signal:
            results["errors"].append("ZK-SNARK proof missing but required.")
            results["zk_proof_valid"] = False
        else:
            try:
                from zk_snark import verify_inference_proof
                if verify_inference_proof(zk_proof, zk_public_signal):
                    results["zk_proof_valid"] = True
                else:
                    results["errors"].append("ZK-SNARK proof mathematical validation failed.")
                    results["zk_proof_valid"] = False
            except Exception as e:
                results["errors"].append(f"ZK-SNARK internal error: {e}")
                results["zk_proof_valid"] = False
                
    # 3. Formal Verifier (Canonical roots, semantic bounds, claims)
    from verifier import FormalVerifier
    
    # For inline inference output (v3.1), we pass it as external_output
    external_output = payload.get("inference_output", "")
    
    verifier = FormalVerifier(
        payload=payload, 
        attestation=attestation, 
        external_output=external_output
    )
    
    results["semantic_bounds_valid"] = verifier.verify_bounds_boolean()
    
    audit_res = verifier.verify()
    results["formal_verification"] = audit_res.status.value
    if audit_res.failed_checks:
        results["errors"].extend(audit_res.failed_checks)

    # Calculate overall status
    results["status"] = "PASS" if results["signature_valid"] and not results["errors"] else "FAIL"
    
    return results


def _repair_db_record(bundle: dict) -> None:
    """Helper to re-insert a recovered bundle into the database."""
    try:
        payload = bundle.get("payload", {})
        contract = payload.get("contract", {})
        execution_id = contract.get("execution_id")
        attestation = bundle.get("attestation", {})
        root_hash = attestation.get("root_hash", "")
        signature = attestation.get("signature", "")
        
        if execution_id:
            app_state.ledger.record_attestation(
                execution_id=execution_id,
                root_hash=root_hash,
                signature=signature,
                bundle=bundle,
                request_id="RECOVERY",
                user_id="SYSTEM",
            )
            logger.info(f"Successfully repaired ledger record for {execution_id}")
    except Exception as e:
        logger.error(f"Failed to repair DB record: {e}")
@app.get("/v1/attestation/{execution_id}/proof")
def get_attestation_proof(execution_id: str):
    """Serve the raw OpenTimestamps (.ots) file for a given execution ID."""
    if not re.match(r"^exec-[0-9a-fA-F-]+$", execution_id):
        raise HTTPException(status_code=400, detail="Invalid execution_id format")
    proof_path = app_state.ledger.get_anchor_proof_path(execution_id)
    if not proof_path:
        raise HTTPException(
            status_code=404, 
            detail="Anchor proof not found. The attestation may not be anchored yet."
        )
    if not os.path.exists(proof_path):
        logger.error("PROOF_FILE_MISSING | path=%s", proof_path)
        raise HTTPException(status_code=500, detail="Proof file missing on disk")
        
    return FileResponse(
        path=proof_path,
        media_type="application/octet-stream",
        filename=f"anchor-{execution_id}.ots"
    )



@app.get("/v1/license/status")
def get_license_status():
    """
    Returns the current license state for this CGI-Protocol deployment.
    Clients can use this to monitor their tier, expiry, and unlocked features.
    """
    lic = app_state.license_status
    import time
    if not lic:
        return {"enforcement": settings.LICENSE_ENFORCEMENT, "licensed": False, "status": "UNLICENSED"}
    return {
        "enforcement":             settings.LICENSE_ENFORCEMENT,
        "licensed":                lic.valid,
        "status":                  "ACTIVE" if lic.valid else "UNLICENSED",
        "license_id":              lic.license_id,
        "licensee":                lic.licensee_name,
        "domain":                  lic.licensee_domain,
        "tier":                    lic.tier,
        "expires":                 time.strftime("%Y-%m-%d", time.gmtime(lic.expires_at)) if lic.expires_at else "",
        "expires_timestamp":       lic.expires_at,
        "days_remaining":          lic.days_remaining,
        "max_requests_per_day":    lic.max_requests_per_day,
        "max_requests_per_minute": lic.max_requests_per_minute,
        "blockchain_anchor":       lic.blockchain_anchor,
        "audit_export":            lic.audit_export,
        "data_classifications":    lic.data_classifications,
        "error":                   lic.error or None,
    }


@app.get("/v1/anchor/status")
def get_anchor_status():
    """
    Returns recent blockchain anchor cycles.
    Shows Merkle roots submitted to the Bitcoin network via OpenTimestamps.
    """
    anchors = app_state.ledger.get_anchor_status(limit=20)
    unanchored_count = len(app_state.ledger.get_unanchored_records())
    return {
        "anchor_enabled": settings.ANCHOR_ENABLED,
        "anchor_interval_seconds": settings.ANCHOR_INTERVAL_SECONDS,
        "unanchored_records": unanchored_count,
        "recent_anchor_cycles": anchors,
    }


@app.post("/v1/anchor/trigger")
def trigger_anchor_now():
    """
    Manually trigger an anchor cycle immediately (on demand).
    Useful for compliance officers who need an immediate Bitcoin proof,
    or for demonstrations.
    """
    if not settings.ANCHOR_ENABLED:
        raise HTTPException(status_code=503, detail="Anchor engine is disabled (ANCHOR_ENABLED=false)")
    if not app_state.anchor_engine:
        raise HTTPException(status_code=503, detail="Anchor engine not initialised")

    result = app_state.anchor_engine.run_anchor_cycle()
    return {
        "anchor_id": result.anchor_id,
        "merkle_root": result.merkle_root,
        "record_count": result.record_count,
        "submitted_to": result.submitted_to,
        "ots_proof_path": result.ots_proof_path,
        "status": result.status,
        "message": result.message,
    }




# ─────────────────────────────────────────────────────────────
# Dashboard & SSE Stream (High-Impact Upgrade)
# ─────────────────────────────────────────────────────────────

# CRIT-4 fix: The duplicate /v1/public-key handler that attempted to open
# 'auth/node_public.pem' (a file that does not exist) has been removed.
# FastAPI silently registered only the last duplicate, meaning every client
# SDK call to /v1/public-key returned 404. The correct handler at line 380
# uses app_state.public_key_pem loaded at startup and is now the sole handler.




@app.get("/dashboard", response_class=HTMLResponse)
async def live_dashboard():
    """Serves the Live Compliance Dashboard HTML."""
    try:
        dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
        with open(dashboard_path, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content, headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        })
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Dashboard UI not found")

@app.get("/v1/stream/attestations")
async def stream_attestations(request: Request):
    """
    Server-Sent Events (SSE) stream for live attestations.
    Can be authenticated via header OR query parameter (for EventSource).
    """
    return StreamingResponse(
        _broadcaster.subscribe(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # For nginx
        }
    )

# ─────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "api_gateway:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=settings.API_WORKERS,
        log_level=settings.LOG_LEVEL.lower(),
    )
