import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import serialization

from contract import InferenceContract
from enclave.attestation import TEEAttestation
from enclave.key_release import RemoteKMS
from merkle import MerkleTree


# =========================================================
# KMS INTEGRATION
# =========================================================
def _get_expected_measurement() -> str:
    h = hashlib.sha384()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for filename in ["cgi_runtime.py", "worker.py"]:
        filepath = os.path.join(base_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                h.update(f.read())
    return h.hexdigest()

# =========================================================
# CONSTANTS
# =========================================================
LOG_DIR = "logs"
AUDIT_FILE = f"{LOG_DIR}/audit.jsonl"
MISSION_FILE = f"{LOG_DIR}/mission_memory.json"
RUNTIME_FILE = f"{LOG_DIR}/runtime_memory.json"
REPLAY_FILE = f"{LOG_DIR}/replay_cache.json"

os.makedirs(LOG_DIR, exist_ok=True)
audit_merkle_tree = MerkleTree()
used_nonce_cache = set()

# =========================================================
# GOVERNANCE KEY (VIA AWS NITRO ATTESTATION)
# =========================================================
print("[BOOT] Requesting Key Release from Remote KMS via TEE Attestation...")

attester = TEEAttestation(enclave_id="nitro-enclave-prod-1")
hardware_quote_bytes = attester.generate_quote(user_data="nonce_for_kms")

kms = RemoteKMS(expected_measurement=_get_expected_measurement())
raw_key_bytes = kms.negotiate_key_release(hardware_quote_bytes)

GOVERNANCE_PRIVATE_KEY = serialization.load_pem_private_key(
    raw_key_bytes,
    password=None
)

# =========================================================
# AUDIT SYSTEM (MERKLE TREE)
# =========================================================
def audit(event, data):
    entry = {
        "timestamp": time.time(),
        "event": event,
        "data": data
    }
    leaf_hash = audit_merkle_tree.add_leaf(entry)
    merkle_root = audit_merkle_tree.get_root()
    proof = audit_merkle_tree.get_proof(len(audit_merkle_tree.leaves) - 1)

    entry["hash"] = leaf_hash
    entry["merkle_root"] = merkle_root

    signature = GOVERNANCE_PRIVATE_KEY.sign(merkle_root.encode("utf-8"))
    entry["signature"] = base64.b64encode(signature).decode("utf-8")
    entry["merkle_proof"] = proof

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry["signature"]

# =========================================================
# RUNTIME LOGIC
# =========================================================
def parse_and_validate_contract(token_payload) -> InferenceContract:
    contract = InferenceContract.from_dict(token_payload["contract"])
    
    audit("RUNTIME_CONTEXT_VALIDATED", {
        "execution_id": contract.execution_id,
        "token_id": token_payload.get("token_id"),
        "model_id": contract.parameters.model_id
    })
    return contract

def generate_portable_attestation(contract: InferenceContract, output_text: str, token_count: int, step_count: int, termination_reason: str, prompt: str, started_at: float, zktls_proofs: list = None, deliberation_transcript=None, optimistic: bool = False):
    print("[ATTESTATION] Generating Portable Attestation Bundle (v3)...")
    if optimistic:
        print("[ATTESTATION] OPTIMISTIC MODE: Bypassing initial ZK-SNARK generation for low latency.")
    





































































































































































































































































































































































































































































