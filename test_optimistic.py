import json
import os
import subprocess
import time
import shutil

print("==================================================")
print(" OPTIMISTIC AI EXECUTION (AVS FRAUD PROOF) TEST")
print("==================================================")

# 1. Clean previous state
if os.path.exists("outputs/portable_attestation.json"):
    os.remove("outputs/portable_attestation.json")
if os.path.exists("logs/replay_cache.json"):
    os.remove("logs/replay_cache.json")

# 2. Generate Auth Token and FHE setup
print("\n[+] Generating Auth Token and FHE payload...")
import sys
sys.path.append(os.path.join(os.path.dirname(__file__)))
from fhe_simulator import FHESimulator
pub_key, priv_key = FHESimulator.generate_keys()
raw_prompt = "AGENT_ACTION"
encrypted_prompt = FHESimulator.encrypt(raw_prompt, pub_key)
with open("auth/prompt_sidechannel.txt", "w", encoding="utf-8") as f:
    f.write(json.dumps(encrypted_prompt.serialize()))
subprocess.run(["venv\\Scripts\\python.exe", "auth\\generate_token.py", "--fhe"], check=True)

# 3. Run Optimistic Inference
print("\n[+] Running Inference in Optimistic Mode (Bypassing ZK-SNARK)...")
start_time = time.time()
subprocess.run(["venv\\Scripts\\python.exe", "cgi_runtime.py", "--optimistic"], check=True)
end_time = time.time()
print(f"[+] Optimistic Execution Completed in {end_time - start_time:.2f} seconds.")

# 4. Analyze Bundle
print("\n[+] Analyzing Portable Attestation Bundle...")
with open("outputs/portable_attestation.json", "r") as f:
    bundle = json.load(f)

runtime_state = bundle["payload"]["runtime_state"]
evidence = bundle["payload"]["evidence"]

is_optimistic = runtime_state.get("is_optimistic", False)
has_zk_proof = "zk_snark_proof" in evidence and evidence["zk_snark_proof"] is not None

print(f"  -> Is Optimistic Mode Active? : {is_optimistic}")
print(f"  -> Is ZK-SNARK omitted?       : {not has_zk_proof}")

if is_optimistic and not has_zk_proof:
    print("\n[SUCCESS] The system successfully bypassed the heavy ZK-SNARK generation.")
    print("          The smart contract (CGIServiceManager.executeOptimistic) will now")
    print("          rely purely on the Hardware TEE Signature (AWS Nitro Quote) for")
    print("          millisecond-latency execution.")
else:
    print("\n[FAIL] Optimistic mode failed to bypass SNARK generation.")
    
# 5. Simulate Challenge
print("\n==================================================")
print(" SIMULATING FRAUD CHALLENGE (DISPUTE RESOLUTION)")
print("==================================================")
print("[!] An auditor challenges the execution on-chain via CGIServiceManager.challengeExecution().")
print("[!] The AI Operator is now forced to generate the ZK-SNARK proof to defend their stake.")

# We simulate the challenge by running the heavy proof generator
print("\n[+] Generating ZK-SNARK Proof (Retroactive)...")
try:
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__)))
    from zk_snark import generate_inference_proof
    proof, public_signal = generate_inference_proof(
        bundle["payload"]["contract"]["prompt_hash"],
        bundle["payload"]["output_commitment"]["output_hash"],
        "model_v1"
    )
    print(f"  -> ZK-SNARK successfully generated: {str(proof)[:40]}...")
    print("\n[SUCCESS] The AI Operator defended their optimistic execution against the challenge.")
except Exception as e:
    print(f"\n[FAIL] Failed to generate ZK-SNARK: {e}")
    print("[!] The AI Operator's EigenLayer restaked assets will be SLASHED.")
