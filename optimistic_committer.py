import hashlib
import time

class OptimisticCommitter:
    """
    Simulates the Optimistic Execution architecture (like opML) for local AI models.
    Instead of generating expensive ZK proofs for every token, it intercepts the 
    inference stream and generates an extremely cheap cryptographic hash (Merkle Root) 
    of the model's intermediate states.
    
    If challenged later, only the specific disputed step is proven using a ZK-SNARK.
    """
    
    def __init__(self, execution_id: str):
        self.execution_id = execution_id
        self.state_trace = []
        
    def commit_trace(self, prompt: str, generated_text: str, logit_fingerprint: str = None) -> str:
        """
        Takes the full inference trace and hashes it into a deterministic state root.
        """
        print(f"[OPTIMISTIC] Generating lightweight state commit for exec_id={self.execution_id}...")
        
        # Simulate state trace commitment (Hashing prompt + tokens)
        self.state_trace.append(hashlib.sha256(prompt.encode()).hexdigest())
        
        # In a real system, we'd hash every token or layer activation. 
        # Here we mock it by chunking the text.
        chunk_size = 10
        for i in range(0, len(generated_text), chunk_size):
            chunk = generated_text[i:i+chunk_size]
            self.state_trace.append(hashlib.sha256(chunk.encode()).hexdigest())
            
        if logit_fingerprint:
            self.state_trace.append(hashlib.sha256(logit_fingerprint.encode()).hexdigest())
            print(f"[OPTIMISTIC] Bound Logit Trajectory Fingerprint to State Root: {logit_fingerprint[:16]}...")
            
        # Compute final Merkle Root of the state trace
        hasher = hashlib.sha256()
        for state in self.state_trace:
            hasher.update(state.encode())
            
        state_root = "0x" + hasher.hexdigest()
        print(f"[OPTIMISTIC] State Root Generated: {state_root}")
        return state_root
