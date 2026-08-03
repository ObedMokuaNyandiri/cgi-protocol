import os
import sys
import json
import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from eth_keys import keys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ATTESTATION_PATH = os.path.join(BASE_DIR, "outputs", "portable_attestation_latest.json")
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "auth", "private_key.pem")

def get_enclave_keypair():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    
    private_numbers = priv_key.private_numbers()
    raw_priv_bytes = private_numbers.private_value.to_bytes(32, byteorder="big")
    
    eth_priv_key = keys.PrivateKey(raw_priv_bytes)
    return eth_priv_key, eth_priv_key.public_key

def main():
    print("============================================================")
    print("  TEST: LOCAL ECRECOVER CRYPTOGRAPHIC BRIDGE")
    print("============================================================\n")

    if not os.path.exists(ATTESTATION_PATH):
        print(f"[!] Attestation not found at: {ATTESTATION_PATH}")
        sys.exit(1)

    print("[1] Loading latest portable attestation...")
    with open(ATTESTATION_PATH, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    # 1. Recreate the hash exactly as the contract will see it
    payload_json = json.dumps(bundle["payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_hash_hex = hashlib.sha256(payload_json).hexdigest()
    msg_hash_bytes = bytes.fromhex(payload_hash_hex)
    print(f"    Payload Hash: 0x{payload_hash_hex}")

    # 2. Extract the DER signature from the Enclave
    b64_sig = bundle["attestation"]["signature"]
    der_sig = base64.b64decode(b64_sig)
    r, s = decode_dss_signature(der_sig)
    
    # EIP-2098 Malleability protection (mimicking Solidity)
    secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > secp256k1n // 2:
        s = secp256k1n - s

    # 3. Get expected public key
    eth_priv, eth_pub = get_enclave_keypair()
    expected_address = eth_pub.to_checksum_address()
    print(f"\n[2] Enclave Target Address: {expected_address}")

    # 4. Brute-force v and test ecrecover math
    found_v = None
    recovered_address = None
    
    for v_id in (0, 1):
        try:
            sig = keys.Signature(vrs=(v_id, r, s))
            recovered_pub = sig.recover_public_key_from_msg_hash(msg_hash_bytes)
            if recovered_pub.to_checksum_address() == expected_address:
                found_v = v_id + 27
                recovered_address = recovered_pub.to_checksum_address()
                break
        except Exception:
            continue
            
    print(f"\n[3] ECRECOVER SIMULATION")
    print(f"    Input Hash : 0x{payload_hash_hex}")
    print(f"    Input r    : 0x{r:064x}")
    print(f"    Input s    : 0x{s:064x}")
    print(f"    Input v    : {found_v}")
    
    print(f"\n[4] VERIFICATION VERDICT")
    print(f"    Expected Signer : {expected_address}")
    print(f"    Recovered Signer: {recovered_address}")
    
    if expected_address == recovered_address:
        print("\n    [SUCCESS] The Python Enclave's DER signature perfectly translates")
        print("              into a valid EVM recoverable signature!")
    else:
        print("\n    [FAILED] Signer mismatch.")
        sys.exit(1)

if __name__ == "__main__":
    main()
