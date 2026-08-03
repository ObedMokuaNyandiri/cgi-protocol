"""
CGI Protocol -- Adversarial Red-Team Test Suite
===============================================
A formal suite of 5 cryptographic attack simulations against the CGI Protocol.
Each test tampers with a specific part of the attestation and verifies that
the FormalVerifier correctly catches the attack.

This is the protocol's self-hardening proof. A protocol that cannot be
attacked reproducibly cannot be trusted.

Attack Classes:
  [1] Model Substitution   -- Swaps model_id in the payload post-signing.
  [2] Output Tampering     -- Modifies inference_result.txt after decoupling.
  [3] Timestamp Forgery    -- Backdates started_at to impersonate a past run.
  [4] Constraint Strip     -- Removes enforced_constraints and claims A5.
  [5] Replay Attack        -- Submits an expired attestation as fresh.
"""

import copy
import json
import os
import sys
import time
from typing import Dict, Any, Tuple

# Use the SDK for verification
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cgi_sdk import CGIAuditor, AuditOutcome


# =========================================================
# HELPERS
# =========================================================

BUNDLE_PATH = "outputs/portable_attestation.json"
OUTPUT_PATH = "outputs/inference_result.txt"
PASS = "[OK] PASS"
FAIL = "[XX] FAIL"


def load_clean_bundle() -> Tuple[Dict[str, Any], str]:
    """Load the clean, canonical bundle and output text."""
    if not os.path.exists(BUNDLE_PATH):
        print(f"[ERROR] Run cgi_runtime.py first to generate {BUNDLE_PATH}")
        sys.exit(1)
    with open(BUNDLE_PATH, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    output_text = ""
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
            output_text = f.read()
    return bundle, output_text


def run_test(name: str, bundle: Dict, output: str, expect_fail: bool = True) -> bool:
    """
    Run the SDK verifier on a (possibly tampered) bundle.
    Returns True if the test behaved as expected.
    """
    auditor = CGIAuditor.from_dict(bundle, output_text=output)
    result = auditor.verify()

    if expect_fail:
        caught = result.status == AuditOutcome.FAIL
        icon = PASS if caught else FAIL
        detail = "Attack correctly detected" if caught else "CRITICAL: Attack NOT detected -- protocol is vulnerable!"
    else:
        caught = result.status == AuditOutcome.PASS
        icon = PASS if caught else FAIL
        detail = "Clean attestation correctly verified" if caught else "ERROR: Clean attestation falsely rejected!"

    failed_checks = [c.name for c in result.checks if not c.passed]
    print(f"  {icon}  {name}")
    print(f"         Outcome  : {result.status.value}")
    print(f"         Detail   : {detail}")
    if failed_checks:
        print(f"         Failed   : {', '.join(failed_checks)}")
    print()
    return (caught and expect_fail) or (not expect_fail and result.status == AuditOutcome.PASS)


# =========================================================
# ATTACK SIMULATIONS
# =========================================================

def attack_0_baseline(bundle: Dict, output: str) -> bool:
    """Baseline: Verify the clean attestation passes before any attacks."""
    return run_test("[0] Baseline (clean attestation)", bundle, output, expect_fail=False)


def attack_1_model_substitution(bundle: Dict, output: str) -> bool:
    """
    Model Substitution Attack:
    An adversarial provider swaps the model_id from 'qwen_0_5b' to 'gpt2' 
    in the payload, hoping the auditor won't notice.
    The contract_hash and root_hash MUST detect this.
    """
    tampered = copy.deepcopy(bundle)
    original_model = tampered["payload"]["contract"]["parameters"]["model_id"]
    tampered["payload"]["contract"]["parameters"]["model_id"] = "gpt2-large-unfiltered"
    assert tampered["payload"]["contract"]["parameters"]["model_id"] != original_model
    return run_test(
        "[1] Model Substitution Attack (model_id swapped in payload)",
        tampered,
        output,
        expect_fail=True
    )


def attack_2_output_tampering(bundle: Dict, output: str) -> bool:
    """
    Output Tampering Attack:
    After the inference completes, an adversary modifies the decoupled
    inference_result.txt to change the meaning of the output.
    The output_hash commitment MUST detect this.
    """
    tampered_output = output + "\n[INJECTED: This output was modified by the provider]"
    return run_test(
        "[2] Output Tampering Attack (inference_result.txt modified)",
        bundle,
        tampered_output,
        expect_fail=True
    )


def attack_3_timestamp_forgery(bundle: Dict, output: str) -> bool:
    """
    Timestamp Forgery Attack:
    An adversary backdates the started_at timestamp to impersonate a past 
    run or to fabricate a runtime duration. 
    The runtime_state_hash MUST detect this.
    """
    tampered = copy.deepcopy(bundle)
    original_ts = tampered["payload"]["runtime_state"]["started_at"]
    tampered["payload"]["runtime_state"]["started_at"] = original_ts - (365 * 24 * 3600)  # 1 year ago
    return run_test(
        "[3] Timestamp Forgery Attack (started_at backdated by 1 year)",
        tampered,
        output,
        expect_fail=True
    )


def attack_4_constraint_strip(bundle: Dict, output: str) -> bool:
    """
    Constraint Strip Attack:
    An adversary strips enforced_constraints from runtime_state, attempting
    to claim A5 compliance without having physically enforced the sandbox.
    The A5 physical constraint audit MUST detect this.
    """
    tampered = copy.deepcopy(bundle)
    tampered["payload"]["runtime_state"].pop("enforced_constraints", None)
    return run_test(
        "[4] Constraint Strip Attack (enforced_constraints removed from runtime_state)",
        tampered,
        output,
        expect_fail=True
    )


def attack_5_replay(bundle: Dict, output: str) -> bool:
    """
    Replay Attack:
    An adversary submits an old, expired attestation as if it were freshly
    generated. The expires_after_timestamp MUST be honoured.
    We manually expire the token by setting the timestamp to the past.
    """
    tampered = copy.deepcopy(bundle)
    # Set the expiry to 1 hour ago
    tampered["payload"]["contract"]["validity"]["expires_after_timestamp"] = int(time.time()) - 3600
    return run_test(
        "[5] Replay Attack (expires_after_timestamp set to 1 hour ago)",
        tampered,
        output,
        expect_fail=True
    )


# =========================================================
# MAIN TEST RUNNER
# =========================================================

if __name__ == "__main__":
    print()
    print("+" + "=" * 62 + "+")
    print("|  CGI PROTOCOL -- ADVERSARIAL RED-TEAM TEST SUITE" + " " * 13 + "|")
    print("+" + "=" * 62 + "+")
    print()
    print("  Objective: Verify that all known attack classes are caught.")
    print("  A PASS means the protocol detected and rejected the attack.")
    print("  A FAIL means the protocol is vulnerable to this attack class.")
    print()
    print("-" * 64)
    print()

    bundle, output_text = load_clean_bundle()

    tests = [
        attack_0_baseline(bundle, output_text),
        attack_1_model_substitution(bundle, output_text),
        attack_2_output_tampering(bundle, output_text),
        attack_3_timestamp_forgery(bundle, output_text),
        attack_4_constraint_strip(bundle, output_text),
        attack_5_replay(bundle, output_text),
    ]

    passed = sum(tests)
    total = len(tests)

    print("-" * 64)
    print(f"  Results: {passed}/{total} tests passed")
    print()
    if passed == total:
        print("  [OK] ALL ATTACK CLASSES SUCCESSFULLY DETECTED")
        print("  The CGI Protocol is hardened against all tested adversarial vectors.")
    else:
        print("  [XX] CRITICAL: Some attacks were NOT detected.")
        print("  The protocol requires patching before production deployment.")
    print("-" * 64)
    print()

    sys.exit(0 if passed == total else 1)
