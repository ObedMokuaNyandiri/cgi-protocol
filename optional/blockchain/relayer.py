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

def get_enclave_public_key() -> keys.PublicKey:
    """Load the Enclave's public key (Ethereum format)."""
    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Extract raw 32-byte private key to use with eth-keys
    private_numbers = priv_key.private_numbers()
    raw_priv_bytes = private_numbers.private_value.to_bytes(32, byteorder="big")
    
    eth_priv_key = keys.PrivateKey(raw_priv_bytes)
    return eth_priv_key.public_key

def main():
    print("============================================================")
    print("  CGI PROTOCOL — ON-CHAIN RELAYER")
    print("============================================================\n")

    if not os.path.exists(ATTESTATION_PATH):
        print(f"[!] Attestation not found at: {ATTESTATION_PATH}")
        sys.exit(1)

    print("[RELAYER] Reading latest portable attestation...")
    with open(ATTESTATION_PATH, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    payload_json = json.dumps(bundle["payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_hash_hex = hashlib.sha256(payload_json).hexdigest()
    
    print(f"[RELAYER] Payload SHA-256 Hash: 0x{payload_hash_hex}")

    # The Enclave produces an ASN.1 DER-encoded signature
    b64_sig = bundle["attestation"]["signature"]
    der_sig = base64.b64decode(b64_sig)

    # Decode r and s from DER
    r, s = decode_dss_signature(der_sig)
    
    print(f"[RELAYER] Extracted 'r': 0x{r:064x}")
    print(f"[RELAYER] Extracted 's': 0x{s:064x}")

    # Fix EIP-2098 Malleability (Solidity contract will reject upper-half 's' values)
    secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    half_order = secp256k1n // 2
    if s > half_order:
        print("[RELAYER] Fixing signature malleability (s > secp256k1n / 2)...")
        s = secp256k1n - s
        print(f"[RELAYER] New 's':       0x{s:064x}")

    # To submit to Ethereum, we need the recovery byte 'v' (27 or 28).
    # Since the Enclave didn't provide 'v', we brute-force it (there are only 2 possibilities)
    # by checking which one recovers the known public key.
    target_pubkey = get_enclave_public_key()
    print(f"[RELAYER] Target Enclave Address: {target_pubkey.to_checksum_address()}")

    msg_hash_bytes = bytes.fromhex(payload_hash_hex)
    
    found_v = None
    for v_id in (0, 1):
        try:
            # Construct signature and try to recover public key
            sig = keys.Signature(vrs=(v_id, r, s))
            recovered_pub = sig.recover_public_key_from_msg_hash(msg_hash_bytes)
            if recovered_pub == target_pubkey:
                found_v = v_id + 27 # Ethereum convention
                break
        except Exception:
            continue
            
    if not found_v:
        print("[!] FATAL: Could not recover target public key using v=27 or v=28.")
        sys.exit(1)

    print(f"[RELAYER] Brute-forced 'v': {found_v}")
    print("\n============================================================")
    print("  READY FOR SMART CONTRACT SUBMISSION")
    print("============================================================")
    
    print(f"\nCall verifyAttestation on CGI_Verifier.sol with the following parameters:\n")
    print(f"rootHash : 0x{payload_hash_hex}")
    print(f"r        : 0x{r:064x}")
    print(f"s        : 0x{s:064x}")
    print(f"v        : {found_v}")
    
    print("\nIf you are using Foundry (cast), run:")
    print(f"cast send <CONTRACT_ADDRESS> \"verifyAttestation(bytes32,bytes32,bytes32,uint8)\" 0x{payload_hash_hex} 0x{r:064x} 0x{s:064x} {found_v} --private-key <YOUR_ETH_PRIVATE_KEY>")
    
    print("\nIf using Remix IDE, pass the following array into verifyAttestation:")
    print(f"[\"0x{payload_hash_hex}\", \"0x{r:064x}\", \"0x{s:064x}\", {found_v}]")

if __name__ == "__main__":
    main()
