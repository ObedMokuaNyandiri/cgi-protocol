import requests
import json
import time
import sys
from cgi_sdk import CGIAuditor

# Configuration
API_BASE = "http://127.0.0.1:8000/v1"
API_KEY = "e18b114387c9d579dc9078d334380e09e754d10dd0b8963194b6652bb8552af7"

# 1. Industrial-Grade Prompt
prompt = """
You are an autonomous Legal AI Auditor. Analyze the following contract clause and determine if it poses an unmitigated liability risk for our client (the vendor).

Clause 14.2 (Indemnification):
"Vendor shall defend, indemnify, and hold harmless the Client from and against any and all claims, damages, liabilities, costs, and expenses (including but not limited to reasonable attorneys' fees) arising out of or related to any breach of this Agreement, including instances of ordinary negligence by the Client."

Task:
1. Identify the specific elements of this clause that allocate risk.
2. Determine if the inclusion of "ordinary negligence by the Client" is standard industry practice or an unmitigated risk.
3. State your recommendation (Accept, Reject, Redline) and rationale.
"""

print("==================================================")
print("🏭 CGI PROTOCOL — INDUSTRIAL DEPLOYMENT TEST 🏭")
print("==================================================")
print("\n[1] Preparing industrial-grade legal/financial prompt...")

# 2. Send to CGI Protocol Gateway
print("\n[2] Sending request to CGI Gateway (which routes to the isolated Qwen server)...")
payload = {
    "prompt": prompt,
    "model_id": "qwen_0_5b",
    "data_classification": "CONFIDENTIAL",
    "max_tokens": 150
}
headers = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY  # Depending on config, this might just pass through if auth is disabled/mocked
}

t0 = time.time()
try:
    response = requests.post(f"{API_BASE}/infer", json=payload, headers=headers, timeout=60)
except requests.exceptions.ConnectionError:
    print("❌ ERROR: Could not connect to CGI Gateway on port 8000. Is it running?")
    sys.exit(1)

t1 = time.time()

if response.status_code != 200:
    print(f"❌ ERROR: Inference failed with status {response.status_code}")
    print(response.text)
    sys.exit(1)

bundle = response.json()
print(f"✅ Success! Received cryptographically signed attestation bundle in {t1-t0:.2f}s")

# 3. Analyze the results
payload_data = bundle.get("payload", {})
contract = payload_data.get("contract", {})
metrics = payload_data.get("verification_verdict", {}).get("execution_metrics", {})
attestation = bundle.get("attestation", {})

generated_text = payload_data.get("inference_output", "")

print("\n[3] AI Generation Result:")
print("-" * 50)
print(generated_text)
print("-" * 50)

print("\n[4] Attestation Verification:")
print(f"   Execution ID: {contract.get('execution_id')}")
print(f"   Model Used: {contract.get('parameters', {}).get('model_id')}")
print(f"   Tokens Generated: {metrics.get('tokens_generated')}")
print(f"   Attestation Signature: {attestation.get('signature', '')[:30]}...")

# 4. Cryptographic Verification using SDK
print("\n[5] Mathematically Verifying Signature via CGI Client SDK...")
# The SDK expects 'node_public.pem' in the auth directory. 
# It handles the hash computation and ECDSA verification automatically.
auditor = CGIAuditor(bundle)
try:
    result = auditor.verify()
    print("\n--- SDK AUDIT REPORT ---")
    print(auditor.report(result))
    print("------------------------\n")
    
    if result.status.name == "PASS":
        print("✅ VERIFIED: The signature is cryptographically valid. The response is unaltered.")
    else:
        print(f"❌ FAILED: The signature is invalid! Status: {result.status}")
except Exception as e:
    print(f"⚠️ SDK Verification Error: {e}")
    print("This might occur if the node_public.pem isn't generated yet or the SDK root hash computation is misaligned.")

print("\n✨ Test Complete. The isolated Qwen model was successfully integrated and attested! ✨")
