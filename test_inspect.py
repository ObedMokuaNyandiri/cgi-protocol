"""
CGI-Protocol — Full Inference Inspection Demo
==============================================
Sends a real enterprise-level prompt to the API Gateway (Qwen model on GCP),
then inspects and displays the complete output: AI response + full
cryptographic attestation bundle — every field, every hash, every signature.
"""
import json
import time
import urllib.error
import urllib.request

# ── Configuration ─────────────────────────────────────────────
API_URL = "http://localhost:8000/v1/infer"
API_KEY = "demo-api-key"

# ── The Challenge Prompt (enterprise-grade, multi-domain) ─────
PROMPT = """You are an AI assistant operating inside a cryptographically governed execution environment.

A senior financial compliance officer has flagged the following transaction for AI review:

  Transaction ID : TXN-881-ALPHA
  Amount         : $2,450,000 USD
  Sender         : Offshore Entity "Nexus Holdings LLC" (Cayman Islands)
  Receiver       : Shell Corp "BrightPath Ventures" (Delaware, 3 months old)
  Pattern        : 47 identical wire transfers in 48 hours, all just below $50,000 threshold
  Risk Score     : 0.94 / 1.00 (AI pre-screen)

Based on this data, provide:
1. A clear verdict: BLOCK, FLAG FOR REVIEW, or APPROVE
2. The specific financial crime typology this matches (e.g., structuring, layering, smurfing)
3. The regulatory framework that mandates reporting (e.g., BSA, FATF, FinCEN)
4. Recommended immediate actions for the compliance team

Be precise and authoritative."""

print("=" * 68)
print("  CGI-Protocol — Enterprise AI Inference + Attestation Inspector")
print("=" * 68)
print(f"\n  Endpoint    : {API_URL}")
print(f"  Model       : Gemini 2.5 Flash (running locally via adapter)")
print(f"  Domain      : FINANCIAL COMPLIANCE")
print(f"  Prompt Len  : {len(PROMPT)} characters")
print("\n" + "─" * 68)
print("  PROMPT SENT TO AI:")
print("─" * 68)
print(PROMPT)
print("─" * 68)

# ── Send Request ──────────────────────────────────────────────
payload = {
    "prompt": PROMPT,
    "data_classification": "CONFIDENTIAL",
    "purpose_of_use": "COMPLIANCE_REVIEW",
    "max_tokens": 200,
}

headers = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
}

req = urllib.request.Request(
    API_URL,
    data=json.dumps(payload).encode("utf-8"),
    headers=headers,
    method="POST",
)

print("\n  Sending to CGI Gateway...")
t0 = time.monotonic()

try:
    with urllib.request.urlopen(req, timeout=120) as response:
        raw = response.read().decode("utf-8")
        elapsed_ms = round((time.monotonic() - t0) * 1000)
        result = json.loads(raw)

    print(f"  Response received in {elapsed_ms}ms\n")

    # ── Section 1: AI Response ────────────────────────────────
    print("=" * 68)
    print("  [1] AI MODEL OUTPUT")
    print("=" * 68)
    ai_output = result.get("payload", {}).get("inference_output", "N/A")
    print(ai_output)

    # ── Section 2: Verification Verdict ──────────────────────
    print("\n" + "=" * 68)
    print("  [2] VERIFICATION VERDICT")
    print("=" * 68)
    verdict = result.get("payload", {}).get("verification_verdict", {})
    print(f"  Status          : {verdict.get('status', 'N/A')}")
    print(f"  Hardware Trust  : {verdict.get('hardware_trust', 'N/A')}")
    print(f"  Model Integrity : {verdict.get('model_integrity', 'N/A')}")
    metrics = verdict.get("execution_metrics", {})
    print(f"  Wall Time       : {metrics.get('wall_duration_ms', 'N/A')} ms")
    print(f"  Tokens Generated: {metrics.get('tokens_generated', 'N/A')}")
    print(f"  Stop Reason     : {metrics.get('stop_reason', 'N/A')}")

    # ── Section 3: Cryptographic Attestation ─────────────────
    print("\n" + "=" * 68)
    print("  [3] CRYPTOGRAPHIC ATTESTATION")
    print("=" * 68)
    attestation = result.get("attestation", {})
    print(f"  Root Hash       : {attestation.get('root_hash', 'N/A')}")
    sig = attestation.get("signature", "N/A")
    print(f"  ECDSA Signature : {sig[:48]}...")
    print(f"  Signed By       : {attestation.get('signed_by', 'N/A')}")
    print(f"  Enclave Mode    : {attestation.get('enclave_mode', 'N/A')}")
    attested_at = attestation.get("attested_at", 0)
    attested_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(attested_at)) if attested_at else "N/A"
    print(f"  Attested At     : {attested_iso}")

    # ── Section 4: Contract Parameters ───────────────────────
    print("\n" + "=" * 68)
    print("  [4] INFERENCE CONTRACT")
    print("=" * 68)
    contract = result.get("payload", {}).get("contract", {})
    print(f"  Execution ID    : {contract.get('execution_id', 'N/A')}")
    print(f"  Prompt Hash     : {contract.get('prompt_hash', 'N/A')}")
    print(f"  Schema Version  : {result.get('schema_version', 'N/A')}")
    params = contract.get("parameters", {})
    print(f"  Model ID        : {params.get('model_id', 'N/A')}")
    print(f"  Classification  : {params.get('data_classification', 'N/A')}")
    print(f"  Purpose of Use  : {params.get('purpose_of_use', 'N/A')}")
    print(f"  Authorized By   : {params.get('authorized_by', 'N/A')}")

    # ── Section 5: Full Raw JSON ──────────────────────────────
    print("\n" + "=" * 68)
    print("  [5] COMPLETE RAW ATTESTATION BUNDLE (JSON)")
    print("=" * 68)
    print(json.dumps(result, indent=2))

    print("\n" + "=" * 68)
    print("  SUMMARY")
    print("=" * 68)
    verdict_status = verdict.get("status", "UNKNOWN")
    if verdict_status == "ATTESTED_AND_VERIFIED":
        print(f"  ✅  Verdict      : {verdict_status}")
        print(f"  ✅  Root Hash    : Cryptographically bound to this exact output")
        print(f"  ✅  Signature    : Verifiable offline with the public key at /v1/public-key")
        print(f"  ✅  Immutability : Can be anchored to Bitcoin via blockchain_anchor.py")
    else:
        print(f"  ⚠   Verdict      : {verdict_status}")

except urllib.error.HTTPError as e:
    print(f"\n  HTTP Error: {e.code}")
    print(e.read().decode("utf-8"))
except Exception as e:
    print(f"\n  Error: {e}")
