import json
import subprocess
import sys

print("--- REPLAY ATTACK TEST ---")
# 1. Generate a token
subprocess.run([sys.executable, "auth/generate_token.py"], check=True)

with open("auth/epoch_token.json", "r") as f:
    epoch_token = f.read()

# Mock sidechannel prompt
fhe_payload = {
    "ciphertext": "mock_encrypted_prompt",
    "key_id": "test_key",
    "commitment": "hash"
}
with open("auth/prompt_sidechannel.txt", "w") as f:
    f.write(json.dumps(fhe_payload))

print("\n--- FIRST EXECUTION ---")
proc1 = subprocess.run(
    [sys.executable, "cgi_runtime.py", "--fhe", json.dumps(fhe_payload), "--auth", epoch_token],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)
print(proc1.stdout)

print("\n--- SECOND EXECUTION (REPLAY) ---")
proc2 = subprocess.run(
    [sys.executable, "cgi_runtime.py", "--fhe", json.dumps(fhe_payload), "--auth", epoch_token],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)
print(proc2.stdout)

if "Replay attack detected!" in proc2.stdout:
    print("\n[SUCCESS] Replay Attack Prevention Verified!")
else:
    print("\n[FAILED] Replay Attack Prevention Failed!")
