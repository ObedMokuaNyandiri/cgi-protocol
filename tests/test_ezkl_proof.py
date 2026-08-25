import os

import pytest
pytest.importorskip("ezkl")

from zk_snark import (
    _compute_public_signals,
    generate_inference_proof,
    verify_inference_proof,
)


def test_generate_and_verify_halo2_proof():
    """
    Tests that the CGI Protocol can generate and mathematically verify 
    an EZKL Halo2 zero-knowledge proof.
    """
    previous_root = "0x0000000000000000000000000000000000000000000000000000000000000001"
    output_hash = "0x0000000000000000000000000000000000000000000000000000000000000002"
    new_root = "0x0000000000000000000000000000000000000000000000000000000000000003"
    
    print("Testing EZKL Proof Generation...")
    proof, public_signal = generate_inference_proof(previous_root, output_hash, new_root)
    
    assert proof is not None
    assert public_signal is not None
    
    print("Testing EZKL Proof Verification...")
    is_valid = verify_inference_proof(proof, public_signal)
    
    assert is_valid == True, "The proof failed cryptographic verification"
    
def test_halo2_proof_rejects_tampering():
    """
    Tests that if the public signals (the inputs/outputs of the circuit) are tampered with,
    the EZKL proof verification properly rejects the proof.
    """
    previous_root = "0x0000000000000000000000000000000000000000000000000000000000000001"
    output_hash = "0x0000000000000000000000000000000000000000000000000000000000000002"
    new_root = "0x0000000000000000000000000000000000000000000000000000000000000003"
    
    proof, _public_signal = generate_inference_proof(previous_root, output_hash, new_root)
    
    # Tamper with the public signal (e.g. an attacker tries to change the output_hash)
    tampered_output_hash = "0x9999999999999999999999999999999999999999999999999999999999999999"
    tampered_public_signal = _compute_public_signals(previous_root, tampered_output_hash, new_root)
    
    print("Testing EZKL Proof Verification Rejection...")
    is_valid = verify_inference_proof(proof, tampered_public_signal)
    
    assert is_valid == False, "The verifier accepted a tampered proof!"

if __name__ == "__main__":
    test_generate_and_verify_halo2_proof()
    test_halo2_proof_rejects_tampering()
    print("[OK] All EZKL Proof ZK tests passed!")
