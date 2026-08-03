import json
import os
import sys
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# =========================================================
# UNIVERSAL AUDITOR CLI (INDEPENDENT VERIFIER)
# =========================================================

def _hash_component(comp) -> str:
    return hashlib.sha256(json.dumps(comp, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

def run_cli(token_path: str, bundle_path: str, output_path: str, sidechannel_path: str):
    print("==================================================")
    print(" CGI-PROTOCOL INDEPENDENT VERIFIER")
    print("==================================================")
    
    if not os.path.exists(bundle_path):
        print(f"ERROR: Attestation bundle missing at {bundle_path}")
        sys.exit(1)
        
    with open(bundle_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
        
    if not os.path.exists(output_path):
        print(f"ERROR: Decoupled output text missing at {output_path}")
        sys.exit(1)
        
    payload = bundle.get("payload", {})
    attestation = bundle.get("attestation", {})
    verdict = payload.get("verification_verdict", {})
    summary = payload.get("generation_summary", {})

    print("[1/3] PARSING CERTIFIED PAYLOAD...")
    
    # 0. Verify the Decoupled Output text
    with open(output_path, "r", encoding="utf-8") as f:
        output_content = f.read()
    computed_output_hash = hashlib.sha256(output_content.encode("utf-8")).hexdigest()
    expected_output_hash = payload.get("output_commitment", {}).get("output_hash")
    if computed_output_hash != expected_output_hash:
        print("[ERROR] Output Tampering Detected! The decoupled output text does not match the signed commitment.")
        sys.exit(1)

    # 1. Recompute the Canonical Hashes
    contract_hash = _hash_component(payload.get("contract"))
    runtime_state_hash = _hash_component(payload.get("runtime_state"))
    runtime_identity_hash = _hash_component(payload.get("runtime_identity"))
    output_commitment_hash = _hash_component(payload.get("output_commitment"))
    evidence_hash = _hash_component(payload.get("evidence"))
    summary_hash = _hash_component(summary)
    verdict_hash = _hash_component(verdict)
    deliberation_hash = _hash_component(payload.get("deliberation", {}))

    computed_root_hash = hashlib.sha256(
        f"{contract_hash}|{runtime_state_hash}|{runtime_identity_hash}|"
        f"{output_commitment_hash}|{evidence_hash}|{summary_hash}|"
        f"{verdict_hash}|{deliberation_hash}"
        .encode("utf-8")
    ).hexdigest()

    if computed_root_hash != attestation.get("root_hash"):
        print("[ERROR] Payload tampering detected! Hashes do not match attestation root.")
        sys.exit(1)

    print("[2/3] VALIDATING TEE HARDWARE SIGNATURE...")
    # In a real environment, this would call AWS NSM or Intel SGX Quote verification.
    # We verify the local governance key signature to prove the TEE signed the final bundle.
    evidence = payload.get("evidence", {})
    # FIX FLAW-010: runtime writes "hardware_attestations" (plural); support both.
    hardware_attestation = (
        evidence.get("hardware_attestations") or evidence.get("hardware_attestation", {})
    )
    fmt = hardware_attestation.get("format", "unknown")
    quote_b64 = hardware_attestation.get("quote_base64", "") or (
        hardware_attestation.get("quotes_base64", [None])[0]
        if hardware_attestation.get("quotes_base64") else ""
    )
    
    if fmt == "aws-nitro-cose":
        print(f"  -> Detected AWS Nitro Enclave Quote")
    elif fmt == "intel-sgx-dcap":
        print(f"  -> Detected Intel SGX DCAP Quote")
    elif fmt == "amd-sev-snp":
        print(f"  -> Detected AMD SEV-SNP Quote")
    else:
        print(f"  -> Detected unknown quote format: {fmt}")

    public_key_path = "auth/public_key.pem"
    if not os.path.exists(public_key_path):
        print("[ERROR] Missing TEE public key for verification.")
        sys.exit(1)

    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    try:
        signature_bytes = base64.b64decode(attestation.get("attestation_signature", ""))
        public_key.verify(signature_bytes, attestation.get("root_hash").encode("utf-8"))
    except Exception as e:
        print(f"[ERROR] TEE Signature is INVALID or Malformed: {e}")
        sys.exit(1)

    zk_required = payload.get("contract", {}).get("obligations", {}).get("zk_proof_required", False)
    if zk_required:
        print("[2.5/3] VERIFYING ZK-SNARK HOMOMORPHIC PROOF...")
        zk_proof = evidence.get("zk_snark_proof")
        zk_public_signal = evidence.get("zk_public_signal")
        
        if not zk_proof or not zk_public_signal:
            print("[ERROR] Contract requires ZK-SNARK, but proof is missing from attestation!")
            sys.exit(1)
            
        try:
            # We must import the module dynamically to verify mathematically
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from zk_snark import verify_inference_proof
            if not verify_inference_proof(zk_proof, zk_public_signal):
                print("[ERROR] ZK-SNARK Mathematical Soundness Check FAILED!")
                sys.exit(1)
            print("  -> ZK-SNARK Proof Verified Successfully.")
        except Exception as e:
            print(f"[ERROR] Failed to verify ZK-SNARK: {e}")
            sys.exit(1)

    print("[3/3] READING CERTIFIED VERDICT...")
    print("\n--------------------------------------------------")
    
    if verdict.get("status") == "PASS":
        print(f" AUDIT SUCCESS: CERTIFIED {verdict.get('assurance_level')} COMPLIANT")
    else:
        print(f" AUDIT FAILED: {verdict.get('status')}")
    print("--------------------------------------------------")
    
    print(json.dumps({"certified_verification": verdict}, indent=2))
    
    if verdict.get("status") == "PASS":
        print("\n--- Execution Details ---")
        print(f"Contract ID   : {payload.get('contract', {}).get('execution_id')}")
        print(f"Model ID      : {payload.get('contract', {}).get('parameters', {}).get('model_id')}")
        print(f"Tokens Gen    : {payload.get('runtime_state', {}).get('tokens_generated')}")
        print(f"Stop Reason   : {summary.get('stop_reason', 'unknown')}")
        print(f"Output Trunc. : {summary.get('output_truncated', False)}")
        print(f"Duration (ms) : {payload.get('runtime_state', {}).get('duration_ms', 0)}")
        print(f"Verified Root : {attestation.get('root_hash')} -> OK")
        print(f"Protocol      : {attestation.get('protocol_version', 'pre-SIP-v10')}")
        
    # ── SIP v10.0: Deliberation Integrity Certificate ────────────────────────
    deliberation = payload.get("deliberation")
    if deliberation:
        is_blind = False
        steps = deliberation.get("thought_steps", [])
        if steps and "<FHE_CIPHERTEXT" in steps[0].get("thought_content", ""):
            is_blind = True

        from deliberation_verifier import DeliberationVerifier
        print("\n" + "="*50)
        title = " SOVEREIGN DELIBERATION VERIFICATION (SIP v10.0)"
        if is_blind:
            title = " BLIND SOVEREIGN DELIBERATION (FHE-zkCoT v11.0)"
        print(title)
        print("="*50)
        dv = DeliberationVerifier()
        dic = dv.verify(bundle)
        print(f" Status       : {dic.get('status')}")
        print(f" Steps Verified : {dic.get('total_steps_verified')}")
        print(f" Genesis      : {dic.get('genesis_commitment')}")
        print(f" Final Chain  : {dic.get('final_commitment')}")
        print("")
        for chk in dic.get("checks", []):
            icon = "[OK]" if chk["passed"] else "[!!]"
            print(f" {icon} {chk['id']} {chk['check']}")
            print(f"      {chk['detail']}")
        print("")
        print(f" VERDICT: {dic.get('verdict')}")
        print("="*50)
        if dic.get("status") != "CERTIFIED" and verdict.get("status") == "PASS":
            print("[WARNING] Execution passed integrity but deliberation proof is not certified.")
        
    print("==================================================")
    
    if verdict.get("status") != "PASS":
        sys.exit(1)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", default="auth/epoch_token.json", help="Path to epoch token (contract)")
    parser.add_argument("--bundle", default="outputs/portable_attestation.json", help="Path to portable attestation bundle")
    parser.add_argument("--output", default="outputs/inference_result.txt", help="Path to decoupled inference text")
    parser.add_argument("--sidechannel", default="auth/prompt_sidechannel.txt", help="Path to prompt sidechannel")
    args = parser.parse_args()
    
    run_cli(args.token, args.bundle, args.output, args.sidechannel)
