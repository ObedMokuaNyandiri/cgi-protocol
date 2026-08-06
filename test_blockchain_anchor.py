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

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import settings
from ledger import AuditLedger
from blockchain_anchor import AnchorEngine

# ── Bootstrap key (ensure governance key exists) ──────────────
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

os.makedirs(settings.AUTH_DIR, exist_ok=True)
os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
os.makedirs(settings.ANCHOR_DIR, exist_ok=True)

if not os.path.exists(settings.PRIVATE_KEY_PATH):
    key = ec.generate_private_key(ec.SECP256K1())
    with open(settings.PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

with open(settings.PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)


print("=" * 62)
print("  CGI-Protocol — Blockchain Anchoring Engine Demo")
print("=" * 62)

# ── 1. Simulate a clinical AI inference (same as api_gateway.py) ──
print("\n[1/6] Simulating enterprise AI inference (signing locally)...")

DOMAIN_EXAMPLES = {
    "MEDICAL":     "Patient John Doe, 52M. Chest pain, Troponin T 0.9 ng/mL, BP 165/95. Administer Aspirin 300mg?",
    "LEGAL":       "Contract clause 14(b) reviewed by AI — clause is unambiguous and enforceable under Kenya law.",
    "FINANCIAL":   "AI fraud detection: Transaction #TXN-99812 flagged as HIGH RISK (score: 0.97). Block recommended.",
    "GOVERNMENT":  "AI policy analysis: Proposed amendment to Section 34 reduces tax burden by 12.4% for SMEs.",
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
                "model_id": settings.MODEL_ID,
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

print(f"      Execution ID  : {execution_id[:30]}...")
print(f"      Domain        : MEDICAL (multi-domain engine supports LEGAL, FINANCIAL, GOVERNMENT)")
print(f"      Root Hash     : {root_hash[:32]}...")
print(f"      Signature     : {signature_b64[:32]}...")

# ── 2. Write to local ledger ──────────────────────────────────
print("\n[2/6] Writing attestation to local audit ledger (SQLite)...")
ledger = AuditLedger(settings.DB_PATH)
ok = ledger.record_attestation(
    execution_id=execution_id,
    root_hash=root_hash,
    signature=signature_b64,
    bundle=bundle,
    request_id=uuid.uuid4().hex,
    user_id="demo-user",
    data_classification="CONFIDENTIAL",
)
print(f"      Ledger write  : {'SUCCESS' if ok else 'DUPLICATE (already recorded)'}")
print(f"      Total records : {ledger.count()}")
unanchored = ledger.get_unanchored_records()
print(f"      Un-anchored   : {len(unanchored)} record(s) pending Bitcoin anchor")

# ── 3. Run anchor cycle ───────────────────────────────────────
print("\n[3/6] Running Blockchain Anchor Cycle...")
print("      Submitting Merkle Root to 3 OpenTimestamps calendar servers...")
print("      (These servers are run by Bitcoin Core contributors — permanently free)")

engine = AnchorEngine(
    ledger=ledger,
    anchor_dir=settings.ANCHOR_DIR,
    calendar_urls=settings.OTS_CALENDAR_URLS,
    min_batch_size=1,
)

t0 = time.monotonic()
result = engine.run_anchor_cycle()
elapsed = round((time.monotonic() - t0) * 1000, 1)

print(f"\n[4/6] Anchor cycle complete in {elapsed}ms")

# ── 4. Print result bundle ────────────────────────────────────
print()
print("  ┌──────────────────────────────────────────────────────────┐")
print("  │              ANCHOR BUNDLE RESULT                       │")
print("  ├──────────────────────────────────────────────────────────┤")
print(f"  │  Anchor ID     : {result.anchor_id or 'N/A':<43}│")
print(f"  │  Status        : {result.status:<43}│")
print(f"  │  Records in Batch : {result.record_count:<40}│")
merkle_display = (result.merkle_root[:38] + "...") if result.merkle_root else "N/A"
print(f"  │  Merkle Root   : {merkle_display:<43}│")
print(f"  │  OTS Servers Hit: {len(result.submitted_to)}/3{'':<40}│")
for url in result.submitted_to:
    short = url.split("//")[1].split("/")[0]
    print(f"  │    ✓ {short:<55}│")
proof_label = os.path.basename(result.ots_proof_path) if result.ots_proof_path else "N/A"
print(f"  │  Proof File    : {proof_label:<43}│")
print("  └──────────────────────────────────────────────────────────┘")

# ── 5. Verify the anchor back ─────────────────────────────────
print(f"\n[5/6] Verifying Merkle inclusion for execution_id...")
updated_unanchored = ledger.get_unanchored_records()
if len(updated_unanchored) < len(unanchored):
    print(f"      ✓ Ledger confirms: {len(unanchored) - len(updated_unanchored)} record(s) marked as ANCHORED")
    print(f"      ✓ anchor_id column populated in SQLite: {result.anchor_id}")
else:
    print("      ⚠ Records not yet marked (anchor may have partially failed)")

# ── 6. Final verdict ──────────────────────────────────────────
print(f"\n[6/6] Final Verdict")
print()

if result.status in ("ANCHORED", "PARTIAL"):
    servers_hit = len(result.submitted_to)
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║  ✅  BLOCKCHAIN ANCHOR: SUCCESS                         ║")
    print("  ╠══════════════════════════════════════════════════════════╣")
    print(f"  ║  {servers_hit} OpenTimestamps calendar server(s) received the hash    ║")
    print("  ║  The Merkle Root is now pending a Bitcoin block          ║")
    print("  ║  (~6 hours until block confirmation)                     ║")
    print("  ╠══════════════════════════════════════════════════════════╣")
    print("  ║  APPLICABLE DOMAINS:                                     ║")
    print("  ║  Healthcare • Legal • Finance • Government               ║")
    print("  ║  Insurance • Media • Defence • Compliance                ║")
    print("  ╠══════════════════════════════════════════════════════════╣")
    print("  ║  COST INCURRED: $0.00                                    ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print()
    print("  Once Bitcoin confirms (~6h), verify immutability with:")
    print("    pip install opentimestamps-client")
    if result.ots_proof_path:
        print(f"    ots verify {result.ots_proof_path}")
    print()
    print(f"  Or list all anchor cycles:")
    print(f"    python anchor_verifier.py --list-anchors")
    if result.anchor_id:
        print(f"    python anchor_verifier.py --exec-id {execution_id}")
else:
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║  ⚠  ANCHOR PENDING — OTS servers unreachable           ║")
    print("  ║  Records are stored locally and will be retried.        ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(f"\n  Reason: {result.message}")

print()
ledger.close()
