import os
import json
import torch
import torch.nn as nn
import ezkl

# ===================================================================
# CGI PROTOCOL -- ZK-ML EZKL CIRCUIT COMPILATION SCRIPT
# ===================================================================
# This automation script bridges a PyTorch Neural Network to a Halo2 
# Zero-Knowledge Circuit using the EZKL framework.
# 
# Pipeline:
# 1. PyTorch -> ONNX Export
# 2. Settings Generation & Calibration (Quantization)
# 3. Circuit Compilation (.compiled)
# 4. Trusted Setup / SRS Fetching
# 5. Cryptographic Setup (Proving Key & Verification Key generation)
# ===================================================================

# -------------------------------------------------------------------
# 1. Define a Mock PyTorch Model (Representative of a network layer)
# -------------------------------------------------------------------
class MockCGILayer(nn.Module):
    def __init__(self, input_dim=64, hidden_dim=128, vocab_size=512):
        super(MockCGILayer, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc1.weight.data.normal_(0, 0.01)
        self.fc1.bias.data.zero_()
        
        self.relu = nn.ReLU()
        
        self.fc2 = nn.Linear(hidden_dim, vocab_size)
        self.fc2.weight.data.normal_(0, 0.01)
        self.fc2.bias.data.zero_()

    def forward(self, x):
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        return x

async def main():
    print("=" * 60)
    print("  CGI Protocol — EZKL ZK-Circuit Compilation Automation")
    print("=" * 60)
    
    # Paths for generated artifacts
    base_dir = os.path.join(os.path.dirname(__file__), "ezkl_artifacts")
    os.makedirs(base_dir, exist_ok=True)

    model_path = os.path.join(base_dir, "network.onnx")
    data_path = os.path.join(base_dir, "input.json")
    settings_path = os.path.join(base_dir, "settings.json")
    compiled_model_path = os.path.join(base_dir, "network.compiled")
    srs_path = os.path.join(base_dir, "kzg.srs")
    vk_path = os.path.join(base_dir, "test.vk")
    pk_path = os.path.join(base_dir, "test.pk")

    # Initialize Model and Dummy Data
    print("\n[1/6] Initializing PyTorch model and generating dummy input...")
    model = MockCGILayer()
    model.eval()

    # BATCH_SIZE=1, INPUT_DIM=64. Scaled down further to prevent overflow in ZK circuit
    x = torch.rand(1, 64, requires_grad=True) * 0.01

    # -------------------------------------------------------------------
    # 2. Export the PyTorch Model to ONNX
    # -------------------------------------------------------------------
    print("[2/6] Exporting PyTorch model to ONNX format...")
    torch.onnx.export(
        model,
        x,
        model_path,
        export_params=True,
        opset_version=15,  # ezkl often works well with 15/18
        do_constant_folding=True,
        input_names=['input'],
        output_names=['output'],
        dynamo=False
    )

    # Save dummy input for calibration
    data = {"input_data": [x.detach().numpy().flatten().tolist()]}
    with open(data_path, "w") as f:
        json.dump(data, f)

    # -------------------------------------------------------------------
    # 3. Generate and Calibrate EZKL Settings (Quantization)
    # -------------------------------------------------------------------
    print("[3/6] Generating and Calibrating EZKL settings...")
    # Generate default settings
    ezkl.gen_settings(model_path, settings_path)
    
    # Calibrate settings using the sample data to optimize quantization scales
    # Target 'accuracy' to avoid decomposition errors on large values
    ezkl.calibrate_settings(
        data_path, 
        model_path, 
        settings_path, 
        "accuracy"
    )

    # -------------------------------------------------------------------
    # 4. Compile the ZK Circuit
    # -------------------------------------------------------------------
    print("[4/6] Compiling the ONNX model into a Halo2 ZK Circuit...")
    ezkl.compile_circuit(model_path, compiled_model_path, settings_path)

    # -------------------------------------------------------------------
    # 5. Fetch Structured Reference String (SRS) for Trusted Setup
    # -------------------------------------------------------------------
    print("[5/6] Enforcing Multi-Party Computation (MPC) Trusted Setup...")
    # Instead of generating a random insecure SRS, we strictly defer to the 
    # verified downloader which enforces a cryptographic hash check against 
    # the official Perpetual Powers of Tau ceremony.
    import subprocess
    import sys
    try:
        subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "download_trusted_srs.py")],
            check=True
        )
    except subprocess.CalledProcessError:
        raise SystemExit("Compilation halted: MPC Trusted Setup verification failed.")

    # -------------------------------------------------------------------
    # 6. Cryptographic Setup (Proving Key & Verifying Key)
    # -------------------------------------------------------------------
    print("[6/6] Generating Proving Key (.pk) and Verifying Key (.vk)...")
    # This step represents the generation of the actual cryptographic parameters.
    # The Prover uses the .pk, and the Verifier (Smart Contract) uses the .vk.
    try:
        res = ezkl.setup(
            model=compiled_model_path,
            vk_path=vk_path,
            pk_path=pk_path,
        )
        if hasattr(res, '__await__'):
            await res
    except BaseException as e:
        print(f"\n[ERROR] ezkl.setup failed: {e}")
        raise SystemExit("Compilation halted: Cryptographic setup failed.")

    print("\n" + "=" * 60)
    print("  [OK] EZKL ZK-CIRCUIT COMPILATION COMPLETE")
    print("=" * 60)
    print(f"  Artifacts saved to: {base_dir}")
    print("  - network.compiled : The Halo2 compiled arithmetic circuit")
    print("  - test.pk          : The Proving Key (for the TEE Enclave)")
    print("  - test.vk          : The Verification Key (for the Smart Contract)")
    print("=" * 60)


if __name__ == "__main__":
    import asyncio
    
    # Run the main execution in an asyncio loop, as some ezkl bindings 
    # (like get_srs) require a running event loop to spawn background tasks.
    asyncio.run(main())
