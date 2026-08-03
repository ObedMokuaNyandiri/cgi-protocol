import base64
import hashlib
import json
import sys

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

API_URL = "http://localhost:8000"

def get_public_key() -> ec.EllipticCurvePublicKey:
    """Fetch the Enclave's public key from the API."""
    print(f"[SDK] Fetching Governance Public Key from {API_URL}/v1/public-key...")
    resp = requests.get(f"{API_URL}/v1/public-key")
    resp.raise_for_status()
    
    pem_data = resp.json()["public_key_pem"].encode("utf-8")
    pub_key = serialization.load_pem_public_key(pem_data)
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise ValueError("Expected ECDSA public key")
    
    print("[SDK] Public Key fetched successfully.")
    return pub_key

def request_inference(prompt: str) -> dict:
    """Send an inference request to the Verifiable API."""
    print(f"\n[SDK] Sending prompt to API: '{prompt}'")
    resp = requests.post(f"{API_URL}/v1/infer", json={
        "prompt": prompt,
        "model_id": "qwen_0_5b",
        "max_tokens": 200
    })
    resp.raise_for_status()
    return resp.json()

def verify_attestation(bundle: dict, public_key: ec.EllipticCurvePublicKey) -> bool:
    """Mathematically verify the attestation without trusting the API."""
    print("\n[SDK] --- VERIFYING CRYPTOGRAPHY OFFLOAD ---")
    
    attestation = bundle.get("attestation", {})
    payload = bundle.get("payload", {})
    
    # 1. Recreate the hash of the payload
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_hash = hashlib.sha256(payload_json).hexdigest()
    
    provided_hash = attestation.get("root_hash", "")
    provided_hash = provided_hash.removeprefix("0x")
        
    if expected_hash != provided_hash:
        print(f"[!] FAILED: Root hash mismatch!\nExpected: {expected_hash}\nProvided: {provided_hash}")
        return False
    
    print(f"[SDK] Root Hash Verified: {expected_hash}")
    
    # 2. Verify the ECDSA Signature
    b64_sig = attestation.get("signature")
    if not b64_sig:
        print("[!] FAILED: No signature found in attestation.")
        return False
        
    der_sig = base64.b64decode(b64_sig)
    
    try:
        public_key.verify(der_sig, payload_json, ec.ECDSA(hashes.SHA256()))
        print("[SDK] ECDSA Signature Verified. The execution is mathematically authentic.")
    except InvalidSignature:
        print("[!] FAILED: Invalid ECDSA Signature!")
        return False
        
    return True

def main():
    print("============================================================")
    print("  CGI PROTOCOL — CLIENT SDK DEMO")
    print("============================================================\n")
    
    try:
        pub_key = get_public_key()
    except requests.exceptions.ConnectionError:
        print(f"[!] Cannot connect to {API_URL}. Is api_gateway.py running?")
        sys.exit(1)
        
    prompt = "Explain why zero-knowledge proofs are useful for privacy."
    bundle = request_inference(prompt)
    
    print("\n[SDK] Inference completed. Received payload and attestation.")
    
    is_valid = verify_attestation(bundle, pub_key)
    
    print("\n============================================================")
    if is_valid:
        print("  VERDICT: ATTESTED_AND_VERIFIED")
        print("  You can 100% trust this AI output.")
    else:
        print("  VERDICT: REJECTED")
        print("  Do not trust this output. It may have been tampered with.")
    print("============================================================")
    
    # Finally, print the actual AI output
    inference_output = bundle.get("payload", {}).get("inference_output", "")
    print(f"\n[AI OUTPUT]:\n{inference_output[:250]}...\n")

if __name__ == "__main__":
    main()
