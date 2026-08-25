"""
End-to-end test for the CGI-Protocol Blockchain Anchoring Engine.
Creates a signed local attestation (simulating what the API Gateway does),
then anchors it to Bitcoin via OpenTimestamps and prints the full proof.
"""
import os
import sys
import time
import uuid
import json
import hashlib
import base64

from config import settings
from ledger import AuditLedger
from blockchain_anchor import AnchorEngine

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def test_blockchain_anchor():
    os.makedirs(settings.AUTH_DIR, exist_ok=True)
    os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
    if not hasattr(settings, 'ANCHOR_DIR'):
        os.makedirs(os.path.join(settings.BASE_DIR, "data"), exist_ok=True)
    
    if not os.path.exists(settings.PRIVATE_KEY_PATH):
        key = ec.generate_private_key(ec.SECP256K1())
        with open(settings.PRIVATE_KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    with open(settings.PRIVATE_KEY_PATH, "rb") as f:
        pw = settings.PRIVATE_KEY_PASSPHRASE.encode("utf-8") if getattr(settings, "PRIVATE_KEY_PASSPHRASE", None) else None
        private_key = serialization.load_pem_private_key(f.read(), password=pw)

    # ── 1. Simulate a clinical AI inference (same as api_gateway.py) ──
    DOMAIN_EXAMPLES = {
        "MEDICAL":     "Patient John Doe, 52M. Chest pain, Troponin T 0.9 ng/mL, BP 165/95. Administer Aspirin 300mg?",
    }

    # Use the medical example for maximum impact
    prompt = DOMAIN_EXAMPLES["MEDICAL"]
    execution_id = f"exec-{uuid.uuid4().hex}"
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    bundle = {
        "schema_version": "cgi-attestation-v3.1",
        "payload": {
            "contract": {
                "execution_id": execution_id,
                "prompt_hash": prompt_hash,
                "domain_context": "MEDICAL",
                "parameters": {
                    "model_id": getattr(settings, 'MODEL_ID', 'test-model'),
                    "data_classification": "CONFIDENTIAL",
                    "purpose_of_use": "CLINICAL_DECISION_SUPPORT",
                }
            },
            "verification_verdict": {
                "status": "ATTESTED_AND_VERIFIED",
                "hardware_trust": "SOFTWARE_SIGNED",
            },
            "inference_output": "Administer Aspirin 300mg immediately. Elevated Troponin indicates acute cardiac event. Escalate to cardiology.",
        }
    }

    payload_bytes = json.dumps(bundle["payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature_bytes = private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    root_hash = "0x" + payload_hash

    bundle["attestation"] = {
        "root_hash": root_hash,
        "signature": signature_b64,
        "signed_by": "governance-key",
        "attested_at": int(time.time()),
    }

    # ── 2. Write to local ledger ──────────────────────────────────
    ledger = AuditLedger(settings.DB_PATH)
    ok = ledger.record_attestation(
        execution_id=execution_id,
        root_hash=root_hash,
        signature=signature_b64,
        bundle=bundle,
        request_id="test-req-id",
        user_id="test-user",
        data_classification="CONFIDENTIAL",
    )
    assert ok, "Failed to record attestation"

    # ── 3. Running Blockchain Anchor Cycle ────────────────────────
    unanchored = ledger.get_unanchored_records()

    engine = AnchorEngine(
        ledger=ledger,
        anchor_dir=settings.ANCHOR_DIR,
        calendar_urls=settings.OTS_CALENDAR_URLS,
        min_batch_size=1,
    )

    result = engine.run_anchor_cycle()

    # ── 5. Verify the anchor back ─────────────────────────────────
    updated_unanchored = ledger.get_unanchored_records()
    assert len(updated_unanchored) < len(unanchored), "Records not marked as anchored"
    assert result.status in ("ANCHORED", "PARTIAL")
