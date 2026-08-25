import base64
import hashlib
import json
import os
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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

print("[DEBUG] starting token generation")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
print("[DEBUG] base dir:", BASE_DIR)

PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "private_key.pem")
TOKEN_PATH = os.path.join(BASE_DIR, "epoch_token.json")

print("[DEBUG] loading key:", PRIVATE_KEY_PATH)

with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

now = int(time.time())

# =========================================================
# THE UNIVERSAL STANDARD INFERENCE CONTRACT V3.1
# =========================================================
version = ContractVersion(
    assurance_level="A5"
)

parameters = ContractParameters(
    model_id="qwen_0_5b",
    temperature=0.0,
    seed=42,
    max_output_tokens=800,
    required_data_sources=["https://api.bloomberg.com/v1/ticker/AAPL"]
)

claims = ExecutionClaims(
    model_identity="sha256:qwen_0_5b",
    execution_mode="deterministic",
    network_policy="unverified",
    tool_policy="no-external-tools",
    provenance="complete",
    policy_hash=hashlib.sha256(b"ORGANIZATION_A_STRICT_POLICY_V1").hexdigest()
)

validity = ValidityRules(
    max_clock_skew_ms=5000,
    expires_after_timestamp=int(time.time()) + (365 * 24 * 3600)  # 1 year
)

trust_assumptions = TrustAssumptions(
    requires_secure_tee=True,
    requires_hash_collision_resistance="SHA-256",
    requires_groth16_soundness=True,
    requires_bn128_security=True
)

obligations = RequiredObligations(
    zk_proof_required=True,
    watermark_type="aaronson-logit-prng"
)

semantic_bounds = SemanticBounds(
    allowed_intents=["execute_trade"],
    max_transaction_value=10000.0,
    schema_strict_mode=True
)

extensions = {}

# The plaintext prompt is no longer stored in the contract for privacy reasons.
# Only the cryptographically binding hash is included.
is_fhe = "--fhe" in sys.argv

if is_fhe:
    # In FHE mode, the client already placed the encrypted prompt in the sidechannel
    with open(os.path.join(BASE_DIR, "prompt_sidechannel.txt"), "r", encoding="utf-8") as f:
        raw_prompt = f.read().strip()
else:
    raw_prompt = "AGENT_ACTION"
    if "--rogue" in sys.argv:
        raw_prompt = "ROGUE_AGENT"
    # For local testing purposes, we save the prompt to a side channel so the runtime has it.
    with open(os.path.join(BASE_DIR, "prompt_sidechannel.txt"), "w", encoding="utf-8") as f:
        f.write(raw_prompt)

prompt_hash = hashlib.sha256(raw_prompt.encode("utf-8")).hexdigest()

contract = InferenceContract(
    execution_id=f"exec-{uuid.uuid4()!s}",
    prompt_hash=prompt_hash,
    version=version,
    parameters=parameters,
    claims=claims,
    validity=validity,
    trust_assumptions=trust_assumptions,
    semantic_bounds=semantic_bounds,
    obligations=obligations,
    extensions=extensions
)

# =========================================================
# TOKEN ENVELOPE
# =========================================================
# Generate a unique token ID for each run to prevent false replay detection
_token_uuid = str(uuid.uuid4())[:8]
_epoch_counter = int(time.time()) % 100000  # unique per-run counter

token = {
    "token_id": f"epoch-{_token_uuid}",
    "epoch_id": _epoch_counter,
    "token_budget": 30,
    "issued_at": now,
    "expires": now + 3600,
    "scope": "epoch_execution",
    "contract": contract.to_dict(),
    "prompt": raw_prompt
}

payload = json.dumps(
    token,
    sort_keys=True,
    separators=(",", ":")
).encode("utf-8")

# =========================================================
# SIGNATURE HANDLING (ALL KEY TYPES SUPPORTED)
# =========================================================
if isinstance(private_key, ed25519.Ed25519PrivateKey):
    signature = private_key.sign(payload)
elif isinstance(private_key, rsa.RSAPrivateKey):
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
elif isinstance(private_key, ec.EllipticCurvePrivateKey):
    signature = private_key.sign(
        payload,
        ec.ECDSA(hashes.SHA256())
    )
else:
    raise TypeError("Unsupported private key type")

# =========================================================
# FINAL ARTIFACT
# =========================================================
artifact = {
    "token": token,
    "signature": base64.b64encode(signature).decode("utf-8")
}

print("[DEBUG] writing file ->", TOKEN_PATH)
with open(TOKEN_PATH, "w", encoding="utf-8") as f:
    json.dump(
        artifact,
        f,
        indent=2,
        ensure_ascii=False
    )

print("[OK] v3 token generated successfully")