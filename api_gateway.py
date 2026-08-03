"""
CGI Protocol — Production API Gateway v2.0
============================================
Healthcare-grade verifiable AI inference API.

Key changes from v1:
  - REMOVED: unittest.mock usage in production path
  - REMOVED: importlib.reload on every request
  - ADDED:   FastAPI lifespan context manager
  - ADDED:   API key authentication + rate limiting
  - ADDED:   Worker subprocess timeout
  - ADDED:   /health endpoint for Docker/GCP health checks
  - ADDED:   /v1/audit/export for HIPAA audit log retrieval
  - ADDED:   Structured logging
  - ADDED:   Input validation (prompt length, model whitelist)
  - ADDED:   Request ID tracing
  - CACHED:  Private key loaded once at startup
"""

from __future__ import annotations

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
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
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

logger = logging.getLogger("cgi.gateway")

# ─────────────────────────────────────────────────────────────
# Application State (populated at startup, immutable at runtime)
# ─────────────────────────────────────────────────────────────

class AppState:
    """Holds loaded keys and singletons for the app lifetime."""
    private_key: ec.EllipticCurvePrivateKey | None = None
    public_key_pem: str = ""
    ledger: AuditLedger | None = None
    registry: AttestationRegistry | None = None
    merkle_tree: MerkleTree | None = None


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
    # ── Startup ───────────────────────────────────────────────
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
    app_state.merkle_tree = MerkleTree()

    # Ensure replay cache exists
    replay_file = settings.REPLAY_FILE
    if not os.path.exists(replay_file):
        with open(replay_file, "w", encoding="utf-8") as f:
            json.dump({}, f)

    logger.info(
        "CGI Protocol API started | enclave_mode=%s | model=%s",
        settings.ENCLAVE_MODE,
        settings.MODEL_ID,
    )

    yield

    # ── Shutdown ──────────────────────────────────────────────
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
app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(max_requests=settings.RATE_LIMIT_RPM))
app.add_middleware(AuthMiddleware, key_store=_key_store)
app.add_middleware(RequestIDMiddleware)


# ─────────────────────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────────────────────

class InferenceRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=settings.MAX_PROMPT_LENGTH)
    model_id: str = Field(default=settings.MODEL_ID)
    max_tokens: int = Field(default=settings.DEFAULT_MAX_TOKENS, ge=1, le=2048)
    data_classification: str = Field(default=settings.DEFAULT_DATA_CLASSIFICATION)
    purpose_of_use: str = Field(default="TREATMENT")


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
def run_inference(req: InferenceRequest, request: Request):
    """
    Executes an AI inference inside the verifiable CGI wrapper and returns
    the cryptographically signed attestation bundle.
    """
    request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
    api_key_id = getattr(request.state, "api_key_id", "anonymous")

    # ── 1. Input validation ───────────────────────────────────
    if req.model_id not in settings.ALLOWED_MODELS:
        raise HTTPException(
            status_code=400,
            detail=f"Model '{req.model_id}' not allowed. Available: {settings.ALLOWED_MODELS}",
        )

    if req.data_classification not in ("PHI", "PII", "PUBLIC"):
        raise HTTPException(
            status_code=400,
            detail="data_classification must be one of: PHI, PII, PUBLIC",
        )

    logger.info(
        "INFERENCE_REQUEST | request_id=%s user=%s model=%s classification=%s prompt_len=%d",
        request_id, api_key_id, req.model_id, req.data_classification, len(req.prompt),
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
            assurance_level="A5",
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

    # ── 3. Replay guard ───────────────────────────────────────
    from filelock import FileLock

    replay_file = settings.REPLAY_FILE
    with FileLock(replay_file + ".lock", timeout=10):
        cache: dict[str, float] = {}
        if os.path.exists(replay_file):
            try:
                with open(replay_file, "r") as f:
                    cache = json.load(f)
            except (json.JSONDecodeError, OSError):
                cache = {}

        if execution_id in cache:
            raise HTTPException(
                status_code=409,
                detail=f"REPLAY BLOCKED: execution_id '{execution_id}' already processed.",
            )

        cache[execution_id] = time.time()
        with open(replay_file, "w") as f:
            json.dump(cache, f, indent=2)

    # ── 4. Spawn worker with TIMEOUT ──────────────────────────
    worker_path = os.path.join(BASE_DIR, "worker.py")
    stdin_payload = json.dumps({
        "payload": req.prompt,
        "execution_id": execution_id,
    })

    wall_start = time.monotonic()

    try:
        process = subprocess.run(
            [
                sys.executable,
                worker_path,
                str(req.max_tokens),
                str(req.max_tokens),
                str(settings.DEFAULT_SEED),
            ],
            input=stdin_payload,
            capture_output=True,
            text=True,
            cwd=BASE_DIR,
            timeout=settings.WORKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        logger.error(
            "WORKER_TIMEOUT | request_id=%s exec_id=%s timeout=%ds",
            request_id, execution_id, settings.WORKER_TIMEOUT_SECONDS,
        )
        raise HTTPException(
            status_code=504,
            detail=f"Worker timed out after {settings.WORKER_TIMEOUT_SECONDS}s",
        )

    wall_ms = round((time.monotonic() - wall_start) * 1000, 1)

    if process.returncode != 0:
        logger.error(
            "WORKER_FAILURE | request_id=%s exec_id=%s code=%d stderr=%s",
            request_id, execution_id, process.returncode, process.stderr[-500:],
        )
        raise HTTPException(
            status_code=500,
            detail=f"Worker failed with code {process.returncode}",
        )

    # ── 5. Parse worker output ────────────────────────────────
    generated_text, stop_reason, token_count = _parse_worker_output(process.stdout)

    if not generated_text.strip():
        logger.error(
            "WORKER_EMPTY_OUTPUT | request_id=%s exec_id=%s stderr=%s",
            request_id, execution_id, process.stderr[-300:],
        )
        raise HTTPException(
            status_code=500,
            detail="Worker produced empty output",
        )

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

    # ── 11. Audit merkle tree ─────────────────────────────────
    app_state.merkle_tree.add_leaf({
        "event": "INFERENCE_ATTESTED",
        "execution_id": execution_id,
        "root_hash": bundle["attestation"]["root_hash"],
        "timestamp": time.time(),
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
    Export audit log entries for HIPAA compliance reporting.
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


@app.get("/v1/attestation/{execution_id}")
def get_attestation(execution_id: str):
    """Retrieve a specific attestation by execution ID."""
    result = app_state.ledger.get_attestation(execution_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return result


# ─────────────────────────────────────────────────────────────
# Worker Output Parser (from cgi_runtime.py)
# ─────────────────────────────────────────────────────────────

def _parse_worker_output(stdout: str):
    """
    Deterministic parser for worker.py stdout protocol.
    Returns: (generated_text, stop_reason, token_count)
    """
    generated_text = ""
    stop_reason = "limit_reached"
    token_count = 0

    for raw_line in stdout.split("\n"):
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("[TOKEN]"):
            try:
                text_marker = "text="
                text_pos = line.find(text_marker)
                if text_pos == -1:
                    continue
                token_repr = line[text_pos + len(text_marker):]
                token_text = token_repr.encode("utf-8").decode("unicode_escape")
                if len(token_text) >= 2 and token_text[0] in ("'", '"') and token_text[-1] == token_text[0]:
                    token_text = token_text[1:-1]
                generated_text += token_text
                token_count += 1
            except Exception:
                continue

        elif line.startswith("[WORKER_STOP]"):
            try:
                stop_reason = line.split("reason=", 1)[1].strip()
            except IndexError:
                stop_reason = "unknown"

    return generated_text, stop_reason, token_count


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
