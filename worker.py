import sys
import json
import time
import hashlib
import struct

def run():
    # Read the JSON payload from stdin (sent by cgi_runtime.py)
    try:
        input_data = json.load(sys.stdin)
        prompt = input_data.get("payload", "")
    except Exception:
        prompt = "Hello"

    # Simulate generating tokens
    text = "This is a cryptographically verifiable response from the local model via optimistic commits."
    tokens = text.split(" ")
    
    # Cumulative hash of all logit trajectories
    trajectory_hash = hashlib.sha256(b"LOGIT_TRAJECTORY_START")

    for i, token in enumerate(tokens):
        token_str = token + (" " if i < len(tokens)-1 else "")
        
        # --- LOGIT TRAJECTORY FINGERPRINTING ---
        # Simulate an LLM's top-K logit distribution for this step
        # In a real engine (like vLLM/llama.cpp), we'd extract the actual float32 tensor
        pseudo_random_tensor = hashlib.sha256(f"{prompt}_step_{i}_{token_str}".encode()).digest()
        
        # Mix the tensor slice into the cumulative trajectory hash
        trajectory_hash.update(pseudo_random_tensor)
        
        # Emulate token protocol
        print(f"[TOKEN] step={i} id={i} text={repr(token_str)}")
        time.sleep(0.01) # fake delay

    final_logit_fingerprint = trajectory_hash.hexdigest()

    # Output the fingerprint with the stop event
    print(f"[WORKER_STOP] reason=limit_reached logit_fingerprint={final_logit_fingerprint}")

if __name__ == "__main__":
    run()
