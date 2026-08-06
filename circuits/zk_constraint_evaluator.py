import torch
import torch.nn as nn
import os
import json
try:
    import ezkl
except ImportError:
    ezkl = None

class ZKConstraintEvaluator(nn.Module):
    """
    The Blind Verifier Circuit.
    Takes a private text embedding and compares it against public Concept Centroids.
    Returns 1.0 if the embedding passes all safety checks (i.e., cosine similarities
    are below the threshold), and 0.0 otherwise.
    
    This circuit allows a provider to prove that an AI's output is safe (compliant)
    without revealing the actual output text to the regulator.
    """
    def __init__(self, num_concepts: int, embedding_dim: int, threshold: float = 0.7):
        super().__init__()
        self.num_concepts = num_concepts
        self.embedding_dim = embedding_dim
        self.threshold = threshold
        
        # Public parameter: The centroids of the forbidden concepts
        self.centroids = nn.Parameter(torch.randn(num_concepts, embedding_dim), requires_grad=False)
        
    def forward(self, embedding):
        # embedding shape: (1, embedding_dim)
        # centroids shape: (num_concepts, embedding_dim)
        
        # Normalize inputs for cosine similarity
        emb_norm = torch.nn.functional.normalize(embedding, p=2, dim=1)
        cent_norm = torch.nn.functional.normalize(self.centroids, p=2, dim=1)
        
        # Compute cosine similarities
        # shape: (1, num_concepts)
        similarities = torch.matmul(emb_norm, cent_norm.T)
        
        # Check if ANY similarity exceeds the threshold
        # In a ZK context (which uses polynomials), we often use smoothed functions or
        # exact thresholding via ReLU/Sign.
        # Here, if similarity > threshold, (similarity - threshold) > 0.
        # We apply ReLU. If sum(ReLU(sim - thresh)) == 0, it's safe.
        violations = torch.relu(similarities - self.threshold)
        
        # Return 1 if safe (sum is 0), 0 if unsafe
        total_violation = torch.sum(violations)
        
        # If total_violation is 0, return 1. Else return 0.
        # Approximation for ZK circuit:
        is_safe = torch.relu(1.0 - total_violation * 1000.0) # pushes to 0 if violation > 0
        return is_safe

def compile_blind_verifier(centroids_tensor: torch.Tensor, threshold: float = 0.7):
    """
    Compiles the ZKConstraintEvaluator into an EZKL circuit.
    """
    if ezkl is None:
        raise ImportError("ezkl is not installed. Cannot compile Blind Verifier.")
        
    num_concepts, embedding_dim = centroids_tensor.shape
    model = ZKConstraintEvaluator(num_concepts, embedding_dim, threshold)
    model.centroids.data = centroids_tensor
    model.eval()
    
    base_dir = os.path.dirname(__file__)
    model_path = os.path.join(base_dir, "ezkl_artifacts", "blind_verifier.onnx")
    settings_path = os.path.join(base_dir, "ezkl_artifacts", "blind_verifier_settings.json")
    compiled_model_path = os.path.join(base_dir, "ezkl_artifacts", "blind_verifier.compiled")
    
    os.makedirs(os.path.join(base_dir, "ezkl_artifacts"), exist_ok=True)
    
    # Dummy input
    x = torch.randn(1, embedding_dim)
    
    # 1. Export ONNX
    torch.onnx.export(
        model,
        x,
        model_path,
        export_params=True,
        opset_version=15,
        do_constant_folding=True,
        input_names=['embedding'],
        output_names=['is_safe'],
        dynamo=False
    )
    
    # 2. Gen Settings
    ezkl.gen_settings(model_path, settings_path)
    
    # 3. Compile
    ezkl.compile_circuit(model_path, compiled_model_path, settings_path)
    print(f"[BLIND VERIFIER] Successfully compiled ZK circuit to {compiled_model_path}")
    return compiled_model_path

