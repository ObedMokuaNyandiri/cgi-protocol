"""
CGI Protocol — Hardened run_demo.py
=====================================
SRE Audit Fixes Applied:
  FLAW-009: ContractParameters constructed with explicit keyword arguments
  FLAW-012: File handles closed properly (no leaked descriptors)
  FLAW-007: Replay cache pre-initialized at the canonical REPLAY_FILE path
  General:  All mock patches explicitly scoped and documented
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import unittest.mock
import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
AUTH_DIR    = os.path.join(BASE_DIR, "auth")
OUTPUT_DIR  = os.path.join(BASE_DIR, "outputs")
LOG_DIR     = os.path.join(BASE_DIR, "logs")

# Must match the constant in cgi_runtime.py (FLAW-007)
REPLAY_FILE = os.path.join(LOG_DIR, "replay_cache.json")


def setup_clean_env() -> tuple[str, str]:
    """Ensure all required directories and seed files exist."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(AUTH_DIR,   exist_ok=True)
    os.makedirs(LOG_DIR,    exist_ok=True)

    # FIX FLAW-007: initialize replay cache at the canonical path that cgi_runtime.py reads
    if not os.path.exists(REPLAY_FILE):
        with open(REPLAY_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)

    # Generate dev signing key if absent
    private_key_path = os.path.join(AUTH_DIR, "private_key.pem")
    if not os.path.exists(private_key_path):
        print("[!] Generating ECDSA dev key for local KMS mock...")
        key = ec.generate_private_key(ec.SECP256K1())
        with open(private_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    return OUTPUT_DIR, AUTH_DIR


def _sign(private_key: Any, payload: bytes) -> bytes:
    """Type-safe signing dispatcher — mirrors cgi_runtime._sign_bytes."""
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(payload)
    elif isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(
            payload,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def generate_demo_token(auth_dir: str, user_prompt: str) -> str:
    """
    Build a signed demo epoch token.
    FIX FLAW-009: all dataclasses use explicit keyword arguments.
    FIX FLAW-001: prompt_hash is computed from the actual prompt.
    FIX FLAW-012: no leaked file handles.
    """
    private_key_path = os.path.join(auth_dir, "private_key.pem")

    # FIX FLAW-012: use context manager — file always closed
    with open(private_key_path, "rb") as key_file:
        key_bytes   = key_file.read()
    private_key = serialization.load_pem_private_key(key_bytes, password=None)

    prompt_hash = hashlib.sha256(user_prompt.encode("utf-8")).hexdigest()

    contract = InferenceContract(
        execution_id=f"exec-{uuid.uuid4().hex}",
        prompt_hash=prompt_hash,   # FIX FLAW-001: real hash of the real prompt
        version=ContractVersion(
            protocol_version="3.1",
            contract_schema="cgi-attestation-v3.1",
            assurance_level="A5",
        ),
        # FIX FLAW-009: explicit keyword args — no silent field order bug
        parameters=ContractParameters(
            model_id="gemini-3.5-flash",
            max_output_tokens=300,
            temperature=0.7,
            seed=42,
            data_classification="CONFIDENTIAL",
            purpose_of_use="GENERAL"
        ),
        claims=ExecutionClaims(
            model_identity="sha256:gemini-3.5-flash",
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
            requires_secure_tee=True,
            requires_hash_collision_resistance="SHA-256",
            requires_groth16_soundness=True,
            requires_bn128_security=True,
        ),
        semantic_bounds=SemanticBounds(
            allowed_intents=["explain", "analyze", "summarize"],
            max_transaction_value=0.0,
            schema_strict_mode=True,
        ),
        obligations=RequiredObligations(
            zk_proof_required=False,
            watermark_type="aaronson-logit-prng",
        ),
        extensions={},
    )

    token: dict[str, Any] = {
        "token_id":     f"demo-{uuid.uuid4().hex[:8]}",
        "epoch_id":     "demo",
        "token_budget": 200,
        "issued_at":    int(time.time()),
        "expires":      int(time.time()) + 3600,
        "scope":        "epoch_execution",
        "prompt":       user_prompt,      # FIX FLAW-001: prompt carried in token
        "contract":     contract.to_dict(),
    }

    payload_bytes = json.dumps(token, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature     = _sign(private_key, payload_bytes)

    artifact: dict[str, Any] = {
        "token":     token,
        "signature": base64.b64encode(signature).decode("utf-8"),
    }

    token_path = os.path.join(auth_dir, "demo_epoch_token.json")
    with open(token_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    return token_path


def main() -> None:
    DIVIDER = "=" * 60
    print(DIVIDER)
    print("  CGI PROTOCOL — LOCAL INFERENCE DEMO (HARDENED)")
    print(DIVIDER)

    _, auth_dir = setup_clean_env()

    import sys
    # Filter out --api
    args = [arg for arg in sys.argv[1:] if arg != "--api"]
    
    # The user's actual query — what the contract commits to
    if len(args) > 0:
        USER_PROMPT = " ".join(args)
    else:
        USER_PROMPT = (
            "Explain the role of cryptographic attestations in verifiable AI inference, "
            "including how they enable trust without requiring the verifier to re-run the model."
        )

    print(f"\n[DEMO] User prompt: {USER_PROMPT[:80]}...")
    token_path = generate_demo_token(auth_dir, USER_PROMPT)
    print(f"[DEMO] Signed epoch token written to: {token_path}\n")

    # Read back the key bytes before entering mock context to avoid leaking
    # a file handle inside the patch scope (FIX FLAW-012)
    private_key_path = os.path.join(auth_dir, "private_key.pem")
    with open(private_key_path, "rb") as kf:
        key_bytes_for_mock = kf.read()

    with unittest.mock.patch.dict("os.environ", {
        "CGI_TOKEN_PATH":       token_path,
    }):
        import cgi_runtime
        
        try:
            runtime = cgi_runtime.CGIRuntime()
            runtime.audit("SYSTEM_BOOT", {})
            print("\n[DEMO] Executing epoch...\n")
            mode = "api" if "--api" in sys.argv else "local"
            bundle  = runtime.run_epoch(mode=mode)
            runtime.audit("SYSTEM_SHUTDOWN", {})
        except PermissionError as e:
            print(f"\n[!] Authorization failure: {e}")
            sys.exit(1)
        except RuntimeError as e:
            print(f"\n[!] Runtime failure: {e}")
            sys.exit(1)

    # ── Print a concise summary of the attestation ──────────────────────
    attest = bundle.get("attestation", {})
    verdict = bundle.get("payload", {}).get("verification_verdict", {})
    metrics = verdict.get("execution_metrics", {})

    print("\n" + DIVIDER)
    print("  ATTESTATION COMPLETE")
    print(DIVIDER)
    print(f"  Status       : {verdict.get('status')}")
    print(f"  Root Hash    : {attest.get('root_hash')}")
    print(f"  Signature    : {attest.get('signature', '')[:40]}...")
    print(f"  Signed By    : {attest.get('signed_by')}")
    print(f"  Duration     : {metrics.get('wall_duration_ms')} ms")
    print(f"  Tokens       : {metrics.get('tokens_generated')}")
    print(f"  Stop Reason  : {metrics.get('stop_reason')}")
    print(f"  Memory (RSS) : {metrics.get('peak_child_memory_mb')} MB")
    print(DIVIDER)
    print("\n  Full bundle  : outputs/portable_attestation_latest.json")
    print(DIVIDER + "\n")


if __name__ == "__main__":
    main()
