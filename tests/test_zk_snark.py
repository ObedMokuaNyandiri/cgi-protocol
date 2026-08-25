import os
import pytest
from zk_snark import _compute_public_signals, generate_inference_proof, verify_inference_proof

def test_compute_public_signals():
    # Deterministic test
    sig = _compute_public_signals("prev_root", "out_hash", "new_root")
    assert sig != ""
    assert isinstance(sig, str)

def test_mock_proof_generation_and_verification():
    # Ensure we use mock
    os.environ["USE_REAL_ZK_CIRCUITS"] = "0"
    
    proof, sig = generate_inference_proof("A", "B", "C")
    
    assert proof["protocol"] == "halo2"
    assert proof["is_mock"] is True
    
    # Should verify correctly
    assert verify_inference_proof(proof, sig) is True
    
    # Modifying the proof data should fail verification
    proof["proof"] = "0xdeadbeef"
    assert verify_inference_proof(proof, sig) is False

def test_mock_proofs_rejected_in_production():
    # If a mock proof is submitted while running in real mode, it must be rejected (H-6)
    os.environ["USE_REAL_ZK_CIRCUITS"] = "1"
    
    # We generated a mock proof previously
    os.environ["USE_REAL_ZK_CIRCUITS"] = "0"
    proof, sig = generate_inference_proof("A", "B", "C")
    
    # Now simulate production
    os.environ["USE_REAL_ZK_CIRCUITS"] = "1"
    assert verify_inference_proof(proof, sig) is False
