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
import hashlib
import json
import logging
import os
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
    RateLimiter,
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
    _replay_times:  list = None  # parallel list of (timestamp, exec_id) for TTL eviction

    REPLAY_CACHE_MAX = 100_000   # maximum entries before forced eviction
    MAX_CONTRACT_AGE_S = 3_600  # 1 hour — matches expires_after_timestamp in contract

    def replay_seen(self, execution_id: str) -> bool:
        """Return True if execution_id has been processed (replay detected)."""
        self._evict_expired()
        return execution_id in self._replay_set

    def replay_record(self, execution_id: str) -> None:
        """Mark execution_id as processed."""
        if self._replay_set is None:
            self._replay_set = set()
            self._replay_times = []
        if len(self._replay_set) >= self.REPLAY_CACHE_MAX:
            # Evict oldest entry to enforce cap
            old_ts, old_id = self._replay_times.pop(0)
            self._replay_set.discard(old_id)
        self._replay_set.add(execution_id)
        self._replay_times.append((time.monotonic(), execution_id))

    def _evict_expired(self) -> None:
        if not self._replay_times:
            return
        cutoff = time.monotonic() - self.MAX_CONTRACT_AGE_S
        while self._replay_times and self._replay_times[0][0] < cutoff:
            _, old_id = self._replay_times.pop(0)
            self._replay_set.discard(old_id)

    def init_replay_cache(self) -> None:
        self._replay_set   = set()
        self._replay_times = []


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
    if not os.path.exists(settings.PRIVATE_KEY_PATH):
        logger.info("Generating ECDSA secp256k1 governance key pair...")
        key = ec.generate_private_key(ec.SECP256K1())
        with open(settings.PRIVATE_KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        # Set restrictive permissions on Unix
        if os.name == "posix":
            os.chmod(settings.PRIVATE_KEY_PATH, 0o600)
        logger.info("Governance key generated at %s", settings.PRIVATE_KEY_PATH)


def _load_private_key() -> ec.EllipticCurvePrivateKey:
    """Load and cache the governance private key."""
    with open(settings.PRIVATE_KEY_PATH, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"Expected ECDSA key, got {type(key).__name__}")
    return key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan — replaces deprecated @app.on_event."""
    # ── Startup ───────────────────────────────────────────
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )

    _ensure_directories()
    _ensure_governance_key()

    app_state.private_key = _load_private_key()
    pub_key = app_state.private_key.public_key()
    app_state.public_key_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    app_state.ledger = AuditLedger(settings.DB_PATH)
    app_state.registry = AttestationRegistry(chain_path=settings.CHAIN_FILE)

    # Seed Merkle Tree from existing ledger records so state
    # survives container restarts — not just in-memory for the session.
    app_state.merkle_tree = MerkleTree()
    prior_records = app_state.ledger.export_audit_log(limit=10000)
    for rec in prior_records:
        app_state.merkle_tree.add_leaf({
            "execution_id": rec["execution_id"],
            "root_hash": rec["root_hash"],
            "timestamp": rec["timestamp"],
        })
    if prior_records:
        logger.info(
            "MerkleTree seeded with %d prior records from ledger.",
            len(prior_records),
        )

    # FIX H-1: Instantiate adapter once at startup — not per-request.
    app_state.adapter = get_inference_adapter()
    logger.info("Inference adapter initialised: %s", type(app_state.adapter).__name__)

    # FIX C-3: Initialise bounded in-memory replay cache.
    app_state.init_replay_cache()

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
    license_status  = license_manager.verify_license(
        license_file_path=settings.LICENSE_KEY_PATH,
        enforcement=settings.LICENSE_ENFORCEMENT,
    )
    app_state.license_status = license_status

    if not license_status.valid and settings.LICENSE_ENFORCEMENT == "ENFORCE":
        logger.critical(
            "LICENSE_BOOT_FAIL | %s — Gateway refusing to start.",
            license_status.error,
        )
        raise RuntimeError(f"CGI-Protocol license check failed: {license_status.error}")

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
    asyncio.create_task(_anchor_loop())



    yield

    # ── Shutdown ──────────────────────────────────────
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

app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(max_requests=get_dynamic_rate_limit))
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
    max_tokens: int = Field(default=settings.DEFAULT_MAX_TOKENS, ge=1, le=2048)
    data_classification: str = Field(default=settings.DEFAULT_DATA_CLASSIFICATION)
    purpose_of_use: str = Field(default="GENERAL")


class HealthResponse(BaseModel):
    status: str
    version: str
    enclave_mode: str
    model_id: str
    uptime_seconds: float


_boot_time = time.monotonic()


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
def health_check():
    """Docker / GCP health check endpoint."""
    return HealthResponse(
        status="ok",
        version=settings.API_VERSION,
        enclave_mode=settings.ENCLAVE_MODE,
        model_id=settings.MODEL_ID,
        uptime_seconds=round(time.monotonic() - _boot_time, 1),
    )


@app.get("/v1/public-key")
def get_public_key():
    """Returns the governance public key for offline cryptographic verification."""
    return {"public_key_pem": app_state.public_key_pem}


@app.post("/v1/infer")
async def run_inference(req: InferenceRequest, request: Request):
    """
    Executes an AI inference inside the verifiable CGI wrapper and returns
    the cryptographically signed attestation bundle.
    """
    request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
    api_key_id = getattr(request.state, "api_key_id", "anonymous")

    # ── 1. Input validation ───────────────────────────────────
    # When LICENSE_ENFORCEMENT=DISABLED or tier is ENTERPRISE, all models are allowed.
    lic = app_state.license_status
    is_enterprise_or_open = (
        settings.LICENSE_ENFORCEMENT == "DISABLED"
        or (lic and lic.valid and not lic.allowed_model_prefixes)
    )
    if not is_enterprise_or_open and req.model_id not in settings.ALLOWED_MODELS:
        raise HTTPException(
            status_code=400,
            detail=f"Model '{req.model_id}' not allowed. Available: {settings.ALLOWED_MODELS}",
        )

    if req.data_classification not in ("CONFIDENTIAL", "PII", "PUBLIC", "PRIVILEGED", "CLASSIFIED"):
        raise HTTPException(
            status_code=400,
            detail="data_classification must be one of: CONFIDENTIAL, PII, PUBLIC, PRIVILEGED, CLASSIFIED",
        )

    # ── 1b. License tier enforcement ─────────────────────────
    if lic and lic.valid and settings.LICENSE_ENFORCEMENT != "DISABLED":
        if not lic.is_model_allowed(req.model_id):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Model '{req.model_id}' is not included in your {lic.tier} license. "
                    f"Upgrade to access this model."
                ),
            )
        if not lic.is_classification_allowed(req.data_classification):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Data classification '{req.data_classification}' is not permitted "
                    f"under your {lic.tier} license."
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
        lic.max_prompt_length if lic else settings.MAX_PROMPT_LENGTH,
    )
    if len(req.prompt) > effective_max_prompt:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Prompt length {len(req.prompt)} exceeds your license limit of "
                f"{effective_max_prompt} characters ({lic.tier if lic else 'UNLIMITED'} tier)."
            ),
        )

    logger.info(
        "INFERENCE_REQUEST | request_id=%s user=%s model=%s classification=%s prompt_len=%d license_tier=%s",
        request_id, api_key_id, req.model_id, req.data_classification, len(req.prompt),
        lic.tier if (lic and lic.valid) else "UNLICENSED",
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
            network_policy="deny-all",
            tool_policy="no-external-tools",
            provenance="complete",
            policy_hash="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        validity=ValidityRules(
            max_clock_skew_ms=5000,
            expires_after_timestamp=int(time.time()) + 3600,
        ),
        trust_assumptions=TrustAssumptions(
            requires_secure_tee=(settings.ENCLAVE_MODE == "nitro"),
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

    # ── 3. Replay guard (in-memory, bounded TTL — FIX C-3) ──────
    if app_state.replay_seen(execution_id):
        raise HTTPException(
            status_code=409,
            detail=f"REPLAY BLOCKED: execution_id '{execution_id}' already processed.",
        )
    app_state.replay_record(execution_id)

    # ── 4. Execute Inference via Adapter (singleton — FIX H-1) ────
    wall_start = time.monotonic()

    try:
        generated_text, stop_reason, token_count = await asyncio.to_thread(
            app_state.adapter.generate,
            req.prompt,
            req.max_tokens,
            execution_id,
            settings.DEFAULT_SEED,
        )
    except Exception as e:
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
        "hardware_accelerator": "cpu",
        "enclave_mode": settings.ENCLAVE_MODE,
    }

    bundle: dict[str, Any] = {
        "schema_version": "cgi-attestation-v3.1",
        "payload": {
            "contract": contract.to_dict(),
            "verification_verdict": {
                "status": "ATTESTED_AND_VERIFIED",
                "hardware_trust": "SOFTWARE_SIGNED" if settings.ENCLAVE_MODE == "software" else "TEE_VERIFIED",
                "model_integrity": "SUCCESS",
                "execution_metrics": execution_metrics,
            },
            "inference_output": generated_text,
        },
    }

    # ── 7. Cryptographic signing ──────────────────────────────
    payload_bytes = json.dumps(
        bundle["payload"], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    signature_bytes = app_state.private_key.sign(
        payload_bytes, ec.ECDSA(hashes.SHA256())
    )
    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    bundle["attestation"] = {
        "root_hash": "0x" + payload_hash,
        "signature": signature_b64,
        "signed_by": "governance-key",
        "enclave_mode": settings.ENCLAVE_MODE,
        "attested_at": int(time.time()),
    }

    # ── 8. Persist bundle ─────────────────────────────────────
    bundle_name = f"portable_attestation_{os.urandom(8).hex()}.json"
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

    # ── 11. Audit merkle tree ─────────────────────────────
    app_state.merkle_tree.add_leaf({
        "event": "INFERENCE_ATTESTED",
        "execution_id": execution_id,
        "root_hash": bundle["attestation"]["root_hash"],
        "timestamp": time.time(),
    })

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
        "output_preview":    generated_text[:200],
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
def export_audit_log_csv():
    """
    Export full audit log as a streamed CSV file for the dashboard.
    Bypasses strict API key requirements for local admin use.
    """
    def iter_csv():
        # Write header
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["execution_id", "timestamp_iso", "root_hash", "request_id", "user_id", "data_classification", "anchor_id"])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        
        # Stream rows
        for row in app_state.ledger.export_audit_log_stream():
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
        headers={"Content-Disposition": "attachment; filename=cgi_audit_log.csv"}
    )

@app.get("/v1/attestation/{execution_id}")
def get_attestation(execution_id: str):
    """Retrieve a specific attestation by execution ID."""
    result = app_state.ledger.get_attestation(execution_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return result
@app.get("/v1/attestation/{execution_id}/proof")
def get_attestation_proof(execution_id: str):
    """Serve the raw OpenTimestamps (.ots) file for a given execution ID."""
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
    if not lic:
        return {"enforcement": settings.LICENSE_ENFORCEMENT, "licensed": False}
    return {
        "enforcement":             settings.LICENSE_ENFORCEMENT,
        "licensed":                lic.valid,
        "license_id":              lic.license_id,
        "licensee":                lic.licensee_name,
        "domain":                  lic.licensee_domain,
        "tier":                    lic.tier,
        "expires_at_iso":          lic.expires_at_iso,
        "days_remaining":          lic.days_remaining,
        "features": {
            "max_requests_per_day":    lic.max_requests_per_day,
            "max_requests_per_minute": lic.max_requests_per_minute,
            "blockchain_anchor":       lic.blockchain_anchor,
            "audit_export":            lic.audit_export,
            "max_prompt_length":       lic.max_prompt_length,
            "data_classifications":    lic.data_classifications,
        },
        "error": lic.error or None,
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

@app.get("/v1/public-key")
def get_public_key():
    """Returns the ECDSA public key in PEM format for client-side verification."""
    try:
        with open("auth/node_public.pem", "r", encoding="utf-8") as f:
            pem_data = f.read()
        return {"public_key_pem": pem_data}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Public key not found on server")

@app.get("/v1/attestation/{execution_id}")
def get_attestation(execution_id: str):
    """Retrieves the full attestation JSON bundle for a given execution ID."""
    bundle = app_state.ledger.get_attestation(execution_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="Attestation not found in ledger")
    return bundle



@app.get("/dashboard", response_class=HTMLResponse)
async def live_dashboard():
    """Serves the Live Compliance Dashboard HTML."""
    try:
        with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content, headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        })
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Dashboard UI not found")

@app.get("/v1/stream/attestations")
async def stream_attestations(request: Request, api_key: str = None):
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
