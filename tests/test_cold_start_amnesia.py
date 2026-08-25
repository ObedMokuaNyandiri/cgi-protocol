import hashlib
import json

from memory_manager import MemoryManager

def mock_keccak256(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()

def test_cold_start_amnesia():
    print("==========================================================")
    print(" HYBRID DA ARCHITECTURE (ARCHIVAL CHECKPOINT) TEST")
    print("==========================================================")

    agent_id = "agent_0x911"
    initial_state = {"portfolio_value": 1000000, "epoch": 0, "last_trade": "NONE"}

    ARCHIVAL_EPOCH_INTERVAL = 100
    lastArchivalEpoch = 0
    agentStateChain = {}

    def mock_execute_optimistic(epoch, prev_root, new_root):
        if epoch - lastArchivalEpoch > ARCHIVAL_EPOCH_INTERVAL:
            return False, "Archival checkpoint required before proceeding"
        agentStateChain[epoch] = new_root
        return True, "Success"

    def mock_checkpoint_archival_state(epoch, full_state_bytes):
        nonlocal lastArchivalEpoch
        expected_root = agentStateChain.get(epoch)
        computed_root = mock_keccak256(full_state_bytes)
        
        if computed_root != expected_root:
            return False, "Invalid state snapshot: hash mismatch"
            
        lastArchivalEpoch = epoch
        return True, "StateCheckpointed Event Emitted (Immortalized to L1)"

    # 1. Simulate 100 Epochs
    print("\n--- PHASE 1: HIGH-FREQUENCY EXECUTION (EigenDA RAM) ---")
    mem_manager = MemoryManager(agent_id=agent_id, initial_state=initial_state)
    agentStateChain[0] = mem_manager.get_current_root()

    print("Simulating 100 fast epochs...")
    for i in range(1, 101):
        payload = json.dumps({"portfolio_value": 1000000 + (i * 1000)})
        prev_root, new_root, delta = mem_manager.apply_action(payload)
        success, msg = mock_execute_optimistic(i, prev_root, new_root)
        assert success, f"Epoch {i} failed: {msg}"

    print(f"[SUCCESS] Reached Epoch 100. Current Portfolio: {mem_manager.state['portfolio_value']}")

    # 2. Hit Checkpoint Limit
    print("\n--- PHASE 2: HITTING THE ARCHIVAL LIMIT ---")
    payload_101 = json.dumps({"portfolio_value": 1101000})
    prev_root_101, new_root_101, delta_101 = mem_manager.apply_action(payload_101)
    success, msg = mock_execute_optimistic(101, prev_root_101, new_root_101)

    assert not success, "Smart Contract did not halt execution."
    print("[SUCCESS] Smart Contract gracefully halted execution at Epoch 101.")
        
    # 3. Perform L1 Checkpoint
    print("\n--- PHASE 3: L1 ARCHIVAL CHECKPOINT (Ethereum Hard Drive) ---")
    state_100 = {
        "epoch": 100, 
        "last_error": None, 
        "last_trade": "NONE", 
        "portfolio_value": 1100000,
        "last_applied_fields": ["portfolio_value"]
    }
    snapshot_bytes_100 = json.dumps(state_100, sort_keys=True, separators=(',', ':')).encode('utf-8')

    success, msg = mock_checkpoint_archival_state(100, snapshot_bytes_100)
    assert success, f"Checkpoint failed: {msg}"
    print("[SUCCESS] Operator successfully checkpointed Epoch 100!")

    # 4. Resume Execution
    print("\n--- PHASE 4: RESUMPTION ---")
    success, msg = mock_execute_optimistic(101, prev_root_101, new_root_101)
    assert success, "Execution still halted."
    print("[SUCCESS] Epoch 101 executed successfully. Agent unlocked!")
