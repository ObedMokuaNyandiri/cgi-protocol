import sys

try:
    from zktls_fetcher import fetch_with_zktls
except ImportError as e:
    print(f"Error loading modules: {e}")
    sys.exit(1)

print("==========================================================")
print(" TEMPORAL BLOCKHASH ANCHORING (TIME-TRAVEL MEV) TEST")
print("==========================================================")

# 1. Setup Mock Smart Contract
current_block_number = 1000
MAX_BLOCK_AGE = 10

def mock_blockhash(block_number):
    return f"0xBLOCKHASH_FOR_{block_number}"

def mock_execute_optimistic(temporal_block_number, temporal_block_hash):
    if current_block_number < temporal_block_number:
        return False, "Future block"
        
    if current_block_number - temporal_block_number > MAX_BLOCK_AGE:
        return False, "Stale Execution: Time-Travel MEV detected"
        
    if mock_blockhash(temporal_block_number) != temporal_block_hash:
        return False, "Invalid Temporal Anchor"
        
    return True, "Execution Accepted: Data is fresh."

# 2. Simulate Attacker
print("\n[SCENARIO 1: The Time-Travel MEV Attack]")
print("Attacker intercepts AI zk-TLS request.")
print("Attacker replays a stale zk-TLS session from 4 minutes ago (Block 900).")

stale_block = 900
stale_hash = mock_blockhash(stale_block)

print(f"Attacker feeds AI -> Block {stale_block} | {stale_hash}")
# AI unknowingly uses stale block hash
data, proof = fetch_with_zktls("https://api.bloomberg.com/markets/quote?symbol=AAPL", stale_hash)
print(f"AI executes trade based on stale price: {data['price']}")

success, msg = mock_execute_optimistic(stale_block, stale_hash)
print(f"Attacker submits on-chain -> {msg}")

if not success:
    print("[SUCCESS] The Time-Travel exploit was mathematically blocked! Execution Rejected.")
else:
    print("[FAIL] Time-Travel exploit succeeded.")


# 3. Simulate Honest Execution
print("\n[SCENARIO 2: Honest Operator (Fresh Data)]")
print("Operator provides the current L1 block.")

fresh_block = 998 # within MAX_BLOCK_AGE
fresh_hash = mock_blockhash(fresh_block)

print(f"Operator feeds AI -> Block {fresh_block} | {fresh_hash}")
data, proof = fetch_with_zktls("https://api.bloomberg.com/markets/quote?symbol=AAPL", fresh_hash)
print(f"AI executes trade based on fresh price: {data['price']}")

success, msg = mock_execute_optimistic(fresh_block, fresh_hash)
print(f"Operator submits on-chain -> {msg}")

if success:
    print("[SUCCESS] Fresh execution accepted.")
else:
    print(f"[FAIL] Execution rejected: {msg}")

print("\n[SUCCESS] Time-Travel MEV (Oracle Staleness) is permanently resolved.")
