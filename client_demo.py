import json
import os
import subprocess
from fhe_simulator import FHESimulator

print("==================================================")
print(" THE BLIND SOVEREIGN (v11.0 FHE-zkCoT) DEMONSTRATION")
print("==================================================")

# 1. Client Generates Keys
print("\n[CLIENT] Generating TFHE Keys...")
pub_key, priv_key = FHESimulator.generate_keys()
print(f"[CLIENT] Public Key: {pub_key.key_id}")

# 2. Client Encrypts Prompt
import sys

if "--malicious" in sys.argv:
    raw_prompt = "ROGUE_AGENT"
elif "--bounds-violation" in sys.argv:
    raw_prompt = "BOUNDS_VIOLATION"
else:
    raw_prompt = "AGENT_ACTION"
print(f"[CLIENT] Raw Prompt: {raw_prompt}")
encrypted_prompt = FHESimulator.encrypt(raw_prompt, pub_key)
print(f"[CLIENT] Encrypted Prompt Commitment: {encrypted_prompt.get_commitment()[:24]}...")

# 3. Write Encrypted Prompt to Sidechannel
# We bypass the standard auth/generate_token.py for the demo and just write the ciphertext
sidechannel_path = "auth/prompt_sidechannel.txt"
with open(sidechannel_path, "w", encoding="utf-8") as f:
    f.write(json.dumps(encrypted_prompt.serialize()))
print(f"[CLIENT] Sent FHE Ciphertext to Enclave Sidechannel.")

# 4. We still need a valid epoch token, so we generate one.
print("\n[SYSTEM] Generating Auth Token...")
subprocess.run(["venv\\Scripts\\python.exe", "auth\\generate_token.py", "--fhe"], check=True)

# 5. Run the Blind Inference
print("\n[SYSTEM] Initiating Blind Inference (Runtime is blind to prompt and thoughts)...")
subprocess.run(["venv\\Scripts\\python.exe", "cgi_runtime.py"], check=True)

# 6. Client Decrypts Output
print("\n==================================================")
print(" CLIENT-SIDE DECRYPTION")
print("==================================================")
output_path = "outputs/inference_result.txt"
if os.path.exists(output_path):
    with open(output_path, "r", encoding="utf-8") as f:
        encrypted_output_json = f.read()
    
    try:
        data = json.loads(encrypted_output_json)
        from fhe_simulator import FHECiphertext
        ct = FHECiphertext.deserialize(data, pub_key)
        
        print(f"[CLIENT] Received Encrypted Output Commitment: {ct.get_commitment()[:24]}...")
        
        decrypted_text = FHESimulator.decrypt(ct, priv_key)
        print("\n[CLIENT] DECRYPTED OUTPUT:")
        print(decrypted_text)
    except Exception as e:
        print(f"[CLIENT] Error decrypting: {e}")
        print("Raw output:", encrypted_output_json)
else:
    print("[ERROR] No inference result found.")

print("\n==================================================")
print(" FHE DEMONSTRATION COMPLETE")
print("==================================================")
