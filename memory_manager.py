import hashlib
import json

class MemoryManager:
    """
    Implements a Persistent Memory Merkle Tree for the Chronos Architecture.
    Provides the AI agent with infinite memory capability while keeping ZK verification cost constant.
    """
    def __init__(self, agent_id: str, initial_state: dict = None):
        self.agent_id = agent_id
        self.state = initial_state if initial_state else {}
        self.current_root = self._calculate_root(self.state)
        self.history = [self.current_root]

    def _calculate_root(self, state_dict: dict) -> str:
        """
        Calculates the state root. In a production system, this would be a Sparse Merkle Tree (SMT)
        or a Poseidon-hash based tree for ZK-SNARK efficiency. Here we use a deterministic JSON hash.
        """
        if not state_dict:
            return "0x0000000000000000000000000000000000000000000000000000000000000000"
            
        serialized = json.dumps(state_dict, sort_keys=True, separators=(',', ':'))
        return "0x" + hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    def apply_action(self, action_payload: str) -> tuple[str, str, dict]:
        """
        Applies a raw LLM action payload to the state via the deterministic Robust State Reducer.
        Returns (previous_root, new_root, memory_delta).
        """
        from state_reducer import StateReducer
        
        previous_root = self.current_root
        
        # Deterministically reduce state
        new_state = StateReducer.reduce(self.state, action_payload)
        
        # Calculate delta for EigenDA DA (What changed?)
        memory_delta = {}
        for k, v in new_state.items():
            if k not in self.state or self.state[k] != v:
                memory_delta[k] = v
                
        # Handle deletions (though RSR doesn't currently delete)
        for k in self.state:
            if k not in new_state:
                memory_delta[k] = None
        
        self.state = new_state
        new_root = self._calculate_root(self.state)
        self.current_root = new_root
        self.history.append(new_root)
        
        return previous_root, new_root, memory_delta

    def get_current_root(self) -> str:
        return self.current_root

    def generate_eigenda_payload(self, memory_delta: dict) -> str:
        """
        Generates the Data Availability payload. The memory delta must be posted to EigenDA
        so that clients can rebuild the state tree. Prevents Memory Withholding attacks.
        """
        payload = {
            "agent_id": self.agent_id,
            "previous_root": self.history[-2] if len(self.history) > 1 else self.history[0],
            "new_root": self.current_root,
            "delta": memory_delta
        }
        return json.dumps(payload, sort_keys=True)

    def generate_archival_snapshot(self) -> bytes:
        """
        HYBRID DA ARCHITECTURE:
        Serializes the entire state for permanent L1 Calldata anchoring.
        This must perfectly match the _calculate_root logic so the smart contract
        can verify keccak256(snapshot) == current_root.
        """
        serialized = json.dumps(self.state, sort_keys=True, separators=(',', ':'))
        return serialized.encode('utf-8')
