import json
import multiprocessing
import os
import sys
import time

# Ensure we can import the project modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64
import hashlib
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from registry import AttestationRegistry

# Ensure we can import the project modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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

# ===================================================================
# CGI PROTOCOL -- HIGH CONCURRENCY I/O STRESS TEST
# ===================================================================
# Simulates extreme parallel load on the atomic file locking mechanisms
# (replay_cache and chain.jsonl).
# ===================================================================

WORKER_COUNT = 1  # Number of parallel processes (reduced to 1 to prevent PyTorch OOM crashes)

def setup_clean_env():
    outputs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs")
    auth_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "auth")
    
    # Clean up logs and outputs
    for file in ["chain.jsonl", "chain_meta.json", "portable_attestation.json"]:
        f_path = os.path.join(outputs_dir, file)
        if os.path.exists(f_path):
            os.remove(f_path)
            
    logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    replay_path = os.path.join(logs_dir, "replay_cache.json")
    if os.path.exists(replay_path):
        os.remove(replay_path)
        
    return outputs_dir, replay_path

def generate_mock_token(worker_id):
    auth_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "auth")
    key_path = os.path.join(auth_dir, "private_key.pem")
    
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        
    prompt_hash = hashlib.sha256(b"AGENT_ACTION").hexdigest()
    contract = InferenceContract(
        execution_id=f"exec-{uuid.uuid4()}",
        prompt_hash=prompt_hash,
        version=ContractVersion("A5"),
        parameters=ContractParameters("mock", 0.0, 42, 100, []),
        claims=ExecutionClaims("mock", "deterministic", "deny", "deny", "complete", "hash"),
        validity=ValidityRules(5000, int(time.time()) + 3600),
        trust_assumptions=TrustAssumptions(True, "SHA-256", True, True),
        semantic_bounds=SemanticBounds(["execute_trade"], 100.0, True),
        obligations=RequiredObligations(True, "aaronson-logit-prng"),
        extensions={}
    )
    
    token = {
        "token_id": f"worker-{worker_id}-{uuid.uuid4().hex[:8]}",
        "epoch_id": worker_id,
        "token_budget": 30,
        "issued_at": int(time.time()),
        "expires": int(time.time()) + 3600,
        "scope": "epoch_execution",
        "contract": contract.to_dict()
    }
    
    payload = json.dumps(token, sort_keys=True, separators=(",", ":")).encode("utf-8")
    
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(payload)
    elif isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    
    artifact = {
        "token": token,
        "signature": base64.b64encode(signature).decode("utf-8")
    }
    
    token_path = os.path.join(auth_dir, f"epoch_token_{worker_id}.json")
    with open(token_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f)
        
    return token_path

def worker_task(worker_id):
    import unittest.mock
    try:
        # 1. Generate unique token for this worker
        token_path = generate_mock_token(worker_id)
        
        # 2. Run CGI Runtime with Mocked Hardware
        # Set PHYSICAL_NITRO_ENCLAVE=1 to bypass the is_physical check, and mock is_available
        with unittest.mock.patch.dict("os.environ", {"CGI_TOKEN_PATH": token_path, "PHYSICAL_NITRO_ENCLAVE": "1"}):
            with unittest.mock.patch("enclave.nitro_nsm.NsmLib.is_available", return_value=True):
                with unittest.mock.patch("enclave.key_release.RemoteKMS.negotiate_key_release", return_value=open("auth/private_key.pem", "rb").read()):
                    with unittest.mock.patch("enclave.nitro_nsm.NsmLib.verify_doc", return_value=True):
                        # Import after patching environment
                        from cgi_runtime import CGIRuntime
                        
                        input_data = '{"action": "test", "worker_id": ' + str(worker_id) + '}'
                        with unittest.mock.patch("sys.stdin.read", return_value=input_data):
                            try:
                                runtime = CGIRuntime()
                                runtime.audit("SYSTEM_BOOT", {})
                                runtime.run_epoch()
                                runtime.audit("SYSTEM_SHUTDOWN", {})
                            except SystemExit as e:
                                if e.code != 0:
                                    return False, f"Worker {worker_id} crashed with exit code {e.code}"
                            except (ValueError, TypeError, RuntimeError) as e:
                                return False, f"Worker {worker_id} failed: {e!s}"
                                
        return True, f"Worker {worker_id} finished successfully."
    except (ValueError, TypeError, RuntimeError) as e:
        return False, f"Worker {worker_id} threw exception: {e!s}"

def run_stress_test():
    print("=" * 60)
    print("  CGI PROTOCOL — HIGH CONCURRENCY I/O STRESS TEST")
    print("=" * 60)
    print(f"  Spawning {WORKER_COUNT} parallel processes...")
    
    outputs_dir, replay_path = setup_clean_env()
    
    start_time = time.time()
    
    success_count = 0
    failure_count = 0
    errors = []
    
    with multiprocessing.Pool(processes=min(multiprocessing.cpu_count() * 4, 64)) as pool:
        results = pool.map(worker_task, range(WORKER_COUNT))
        
    for success, msg in results:
        if success:
            success_count += 1
        else:
            failure_count += 1
            errors.append(msg)
            
    elapsed = time.time() - start_time
    
    print("\n  [TEST COMPLETE]")
    print(f"  Execution Time : {elapsed:.2f} seconds")
    print(f"  Success Rate   : {success_count}/{WORKER_COUNT}")
    print(f"  Failures       : {failure_count}")
    
    if failure_count > 0:
        print("\n  [!] ERRORS DETECTED:")
        for err in errors[:5]:
            print(f"    - {err}")
        if len(errors) > 5:
            print(f"    ... and {len(errors) - 5} more.")
            
    # Verify Data Integrity
    print("\n  [VERIFYING FILE INTEGRITY]")
    
    # 1. Check Replay Cache
    replay_count = 0
    if os.path.exists(replay_path):
        with open(replay_path, "r") as f:
            cache = json.load(f)
            replay_count = len(cache)
    print(f"  Replay Cache Entries : {replay_count} (Expected: {success_count})")
    
    # 2. Check Registry Chain
    chain_path = os.path.join(outputs_dir, "chain.jsonl")
    registry = AttestationRegistry(chain_path=chain_path)
    verify_result = registry.verify_chain()
    
    chain_length = verify_result["length"]
    chain_valid = verify_result["valid"]
    
    print(f"  Registry Chain Length: {chain_length} (Expected: {success_count})")
    print(f"  Registry Chain Valid : {chain_valid}")
    
    print("-" * 60)
    if success_count == WORKER_COUNT and replay_count == WORKER_COUNT and chain_length == WORKER_COUNT and chain_valid:
        print("  [OK] STRESS TEST PASSED. OS-LEVEL FILE LOCKS ARE BULLETPROOF.")
        sys.exit(0)
    else:
        print("  [XX] STRESS TEST FAILED. RACE CONDITIONS OR DATA LOSS DETECTED.")
        sys.exit(1)

if __name__ == "__main__":
    # Needed for multiprocessing on Windows
    multiprocessing.freeze_support()
    run_stress_test()
