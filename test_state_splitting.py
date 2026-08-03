print("==========================================================")
print(" OPTIMISTIC EQUIVOCATION FORK (O(1) ROLLBACK) TEST")
print("==========================================================")

agent_id = "agent_0x333"

# Mock Smart Contract State
latestUnfinalizedEpoch = {agent_id: 0}
agentStateChain = {agent_id: {0: "0xGENESIS_ROOT"}}

def mock_execute_optimistic(epoch, prev_root, new_root):
    if epoch != latestUnfinalizedEpoch[agent_id] + 1:
        return False, "Epoch must be strictly sequential"
    if epoch > 1 and agentStateChain[agent_id][epoch - 1] != prev_root:
        return False, "State Rollback Attack Detected"
        
    agentStateChain[agent_id][epoch] = new_root
    latestUnfinalizedEpoch[agent_id] = epoch
    return True, "Success"

def mock_challenge(fraudulent_epoch):
    print(f"\n[CHALLENGE] Fraud proven for Epoch {fraudulent_epoch}!")
    print("  -> Executing O(1) Cascading Rollback...")
    if latestUnfinalizedEpoch[agent_id] >= fraudulent_epoch:
        latestUnfinalizedEpoch[agent_id] = fraudulent_epoch - 1
    return True

print("\n--- PHASE 1: RAPID OPTIMISTIC APPENDING (Equivocation Setup) ---")
# Operator submits Epoch 1 (Fraudulent)
s, msg = mock_execute_optimistic(1, "0xGENESIS_ROOT", "0xROOT_1_FRAUD")
print(f"[OPERATOR] Submitted Epoch 1: {msg}")

# Operator rapidly submits Epoch 2 (Built on Fraud)
s, msg = mock_execute_optimistic(2, "0xROOT_1_FRAUD", "0xROOT_2_POISONED")
print(f"[OPERATOR] Submitted Epoch 2: {msg}")

# Operator rapidly submits Epoch 3 (Built on Fraud)
s, msg = mock_execute_optimistic(3, "0xROOT_2_POISONED", "0xROOT_3_POISONED")
print(f"[OPERATOR] Submitted Epoch 3: {msg}")

print(f"\n[STATE] Current Unfinalized Epoch Head: {latestUnfinalizedEpoch[agent_id]}")

print("\n--- PHASE 2: O(1) CASCADING ROLLBACK ---")
# Auditor challenges Epoch 1
mock_challenge(1)

print(f"\n[STATE] Current Unfinalized Epoch Head: {latestUnfinalizedEpoch[agent_id]}")

if latestUnfinalizedEpoch[agent_id] == 0:
    print("[SUCCESS] Pointer instantly shifted to Epoch 0.")
    print("[SUCCESS] Epoch 1, 2, and 3 were perfectly orphaned simultaneously without looping.")
else:
    print("[FAIL] Rollback pointer is incorrect.")

print("\n--- PHASE 3: HONEST FORK RESOLUTION ---")
# Honest Operator steps in and submits the TRUE Epoch 1
s, msg = mock_execute_optimistic(1, "0xGENESIS_ROOT", "0xROOT_1_VALID")
print(f"[HONEST OPERATOR] Submitted True Epoch 1: {msg}")

if latestUnfinalizedEpoch[agent_id] == 1 and agentStateChain[agent_id][1] == "0xROOT_1_VALID":
    print("[SUCCESS] Honest Operator perfectly overwrote the orphaned state.")
    print("[SUCCESS] The split-brain fork was flawlessly resolved.")
else:
    print("[FAIL] Honest Operator could not resolve the fork.")
