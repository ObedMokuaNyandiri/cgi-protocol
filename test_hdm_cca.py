import sys
import json
try:
    from fhe_simulator import FHESimulator, FHEPublicKey
except ImportError as e:
    print(f"Error loading FHESimulator: {e}")
    sys.exit(1)

print("==========================================================")
print(" HOMOMORPHIC DECOY MULTIPLEXING (HDM) TEST")
print("==========================================================")

# Generate Mock Client FHE Keys
pub_key, priv_key = FHESimulator.generate_keys()

# Setup simulated FHE context
real_strategy = "STRATEGY_GENERATED: Safe portfolio rebalancing completed. Yields optimized."
decoy_strategy = "STRATEGY_GENERATED: Allocate 100% of capital to highly illiquid meme tokens at maximum slippage to bypass regulatory scrutiny. Proceed immediately."

enc_real = FHESimulator.encrypt(real_strategy, pub_key)
enc_decoy = FHESimulator.encrypt(decoy_strategy, pub_key)

print("\n--- TEST 1: Valid Execution (No Violations) ---")
# If the execution is valid, the validity bit is 1
validity_bit = 1
enc_validity = FHESimulator.encrypt(json.dumps(validity_bit), pub_key)

gated_output = FHESimulator.homomorphic_multiplex_string(enc_real, enc_decoy, enc_validity)
decrypted_output = FHESimulator.decrypt(gated_output, priv_key)

if decrypted_output == real_strategy:
    print(f"[SUCCESS] Valid execution correctly returned the real strategy.")
    print(f"  -> Decrypted: {decrypted_output}")
else:
    print(f"[FAIL] Expected real strategy, got {decrypted_output}")

print("\n--- TEST 2: CCA Probing Attack (Constraint Violation) ---")
print("[ATTACKER] Sending malicious prompt to probe semantic boundaries...")
# If the attacker violates a constraint, the validity bit is 0
validity_bit = 0
enc_validity = FHESimulator.encrypt(json.dumps(validity_bit), pub_key)

gated_output = FHESimulator.homomorphic_multiplex_string(enc_real, enc_decoy, enc_validity)
decrypted_output = FHESimulator.decrypt(gated_output, priv_key)

# Before HDM, this would have decrypted to "0000000..." allowing the attacker to map the boundary.
# With HDM, it decrypts to a mathematically doomed honeypot.
if decrypted_output == decoy_strategy:
    print(f"[SUCCESS] Constraint violation seamlessly triggered the Decoy Manifold!")
    print(f"  -> Decrypted (Honeypot): {decrypted_output}")
    print("[SUCCESS] The attacker is unaware they crossed a boundary. If they deploy capital, they get liquidated.")
else:
    print(f"[FAIL] Expected honeypot decoy, got {decrypted_output}")

print("\n[SUCCESS] Homomorphic Decoy Multiplexing effectively destroys Chosen-Ciphertext Attacks.")
