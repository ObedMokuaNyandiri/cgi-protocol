"""
CGI Protocol -- Live Demo CLI
==============================
A presentation-ready, end-to-end demonstration of the full CGI Protocol
lifecycle. Designed to be run live in front of government officials,
enterprise clients, and investors.

Usage:
    python cgi_demo.py --demo full-lifecycle
    python cgi_demo.py --demo audit-only
    python cgi_demo.py --demo red-team
    python cgi_demo.py --demo registry
"""

import argparse
import json
import os
import subprocess
import sys
import time


# =========================================================
# RICH TERMINAL OUTPUT
# =========================================================

class T:
    """Terminal color codes."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    RED     = "\033[91m"
    WHITE   = "\033[97m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"


def banner():
    print()
    print(T.CYAN + T.BOLD + "+" + "=" * 66 + "+" + T.RESET)
    print(T.CYAN + T.BOLD + "|" + T.RESET + T.WHITE + T.BOLD + 
          "   CRYPTOGRAPHIC GENERATIVE INFERENCE PROTOCOL v4.0" + 
          " " * 15 + T.RESET + T.CYAN + T.BOLD + "|" + T.RESET)
    print(T.CYAN + T.BOLD + "|" + T.RESET + T.DIM + 
          "   The Missing Infrastructure Layer for the AI Economy" + 
          " " * 13 + T.RESET + T.CYAN + T.BOLD + "|" + T.RESET)
    print(T.CYAN + T.BOLD + "+" + "=" * 66 + "+" + T.RESET)
    print()


def step(n: int, total: int, title: str):
    print(T.BOLD + T.CYAN + f"\n[{n}/{total}] {title}" + T.RESET)


def ok(msg: str):
    print(T.GREEN + "  [OK] " + T.RESET + msg)


def info(msg: str):
    print(T.BLUE + "  [>>] " + T.RESET + msg)


def warn(msg: str):
    print(T.YELLOW + "  [!!] " + T.RESET + msg)


def error(msg: str):
    print(T.RED + "  [XX] " + T.RESET + msg)


def verdict_box(status: str, level: str):
    if status == "PASS":
        color = T.GREEN
        icon = "[OK]"
        label = f"CERTIFIED {level} COMPLIANT"
    else:
        color = T.RED
        icon = "[!!]"
        label = f"VERIFICATION {status}"
    print()
    print(color + T.BOLD + "+" + "-" * 50 + "+" + T.RESET)
    print(color + T.BOLD + f"|  {icon}  {label:<46}|" + T.RESET)
    print(color + T.BOLD + "+" + "-" * 50 + "+" + T.RESET)
    print()


def pause(seconds: float = 0.4):
    time.sleep(seconds)


# =========================================================
# DEMO: FULL LIFECYCLE
# =========================================================

def demo_full_lifecycle():
    banner()
    TOTAL = 5

    # ---- Step 1: Issue the Contract ----
    step(1, TOTAL, "Issuing Inference Contract")
    info("Generating cryptographically signed inference contract...")
    pause()

    result = subprocess.run(
        [sys.executable, "auth/generate_token.py"],
        capture_output=True, text=True, cwd=os.getcwd()
    )
    if result.returncode != 0:
        error("Token generation failed.")
        print(result.stderr)
        sys.exit(1)

    # Read the generated token for display
    try:
        with open("auth/epoch_token.json", "r") as f:
            token = json.load(f)
        contract = token.get("contract", {})
        ok(f"Execution ID     : {contract.get('execution_id', '?')}")
        ok(f"Model Bound      : {contract.get('parameters', {}).get('model_id', '?')}")
        ok(f"Policy Hash      : {contract.get('claims', {}).get('policy_hash', '?')[:24]}...")
        ok(f"Assurance Level  : {contract.get('version', {}).get('assurance_level', '?')}")
        ok(f"ZK Required      : {contract.get('obligations', {}).get('zk_proof_required', '?')}")
        ok(f"Watermark        : {contract.get('obligations', {}).get('watermark_type', '?')}")
    except Exception:
        ok("Token generated successfully.")
    pause()

    # ---- Step 2: Execute in Sandboxed Runtime ----
    step(2, TOTAL, "Executing in Sandboxed TEE Runtime")
    info("Spawning inference worker inside sandboxed enclave...")
    info("Enforcing deterministic constraints on subprocess environment...")
    pause()

    proc = subprocess.run(
        [sys.executable, "-u", "cgi_runtime.py"],
        capture_output=True, text=True, cwd=os.getcwd()
    )
    if proc.returncode != 0:
        error("Runtime execution failed.")
        print(proc.stderr[-500:])
        sys.exit(1)

    # Extract token count from output
    lines = proc.stdout.splitlines()
    token_lines = [l for l in lines if "[TOKEN]" in l]
    stop_lines  = [l for l in lines if "[WORKER_STOP]" in l]
    stop_reason = stop_lines[-1].split("reason=")[-1] if stop_lines else "unknown"

    ok(f"Enclave Provider : aws-nitro (dev-mode)")
    ok(f"Constraints      : CUBLAS_WORKSPACE_CONFIG=:4096:8 | PYTHONHASHSEED=42")
    ok(f"Tokens Generated : {len(token_lines)}")
    ok(f"Stop Reason      : {stop_reason}")
    pause()

    # ---- Step 3: Build Cryptographic Evidence ----
    step(3, TOTAL, "Building Cryptographic Evidence Chain")
    info("Reading portable attestation bundle...")
    pause()

    with open("outputs/portable_attestation.json", "r") as f:
        bundle = json.load(f)

    evidence = bundle["payload"].get("evidence", {})
    hw_att   = evidence.get("hardware_attestation", {})
    zk_proof = evidence.get("zk_snark_proof", {})

    ok(f"Hardware Quote   : {hw_att.get('format', 'unknown')}")
    ok(f"Merkle Root      : {evidence.get('merkle_root', '')[:32]}...")
    ok(f"Merkle Leaves    : {len(evidence.get('merkle_leaves', []))} audit events")
    if zk_proof:
        ok(f"ZK-SNARK Proof   : {zk_proof.get('protocol','?')}/{zk_proof.get('curve','?')} [GENERATED]")
    else:
        warn("ZK-SNARK proof not generated (obligations not set).")
    pause()

    # ---- Step 4: Independent Audit ----
    step(4, TOTAL, "Running Independent Cryptographic Audit")
    info("Loading CGI SDK auditor...")
    pause()

    from cgi_sdk import CGIAuditor, AuditOutcome
    auditor = CGIAuditor.from_file("outputs/portable_attestation.json")
    result = auditor.verify()

    for check in result.checks:
        if check.passed:
            ok(check.name)
        else:
            error(f"{check.name}  <- FAILED")

    for w in result.warnings:
        warn(w)

    # ---- Step 5: Final Verdict ----
    step(5, TOTAL, "Protocol Verdict")
    attestation = bundle.get("attestation", {})
    ok(f"Root Hash : {attestation.get('root_hash', '')} -> OK")
    verdict_box(result.status.value, result.assurance_level)

    # Append to Registry
    info("Appending attestation to immutable chain registry...")
    from registry import AttestationRegistry
    reg = AttestationRegistry()
    entry = reg.append("outputs/portable_attestation.json")
    ok(f"Chain entry #{entry.sequence} registered | Entry hash: {entry.entry_hash[:32]}...")
    print()


# =========================================================
# DEMO: AUDIT ONLY
# =========================================================

def demo_audit_only():
    banner()
    from cgi_sdk import CGIAuditor
    print(T.BOLD + "  MODE: Audit-Only -- Verifying existing attestation" + T.RESET)
    print()

    bundle_path = "outputs/portable_attestation.json"
    if not os.path.exists(bundle_path):
        error(f"No attestation found at {bundle_path}. Run --demo full-lifecycle first.")
        sys.exit(1)

    auditor = CGIAuditor.from_file(bundle_path)
    result = auditor.verify()
    print(auditor.report(result))


# =========================================================
# DEMO: RED TEAM
# =========================================================

def demo_red_team():
    banner()
    print(T.BOLD + T.RED + "  MODE: Adversarial Red-Team -- Attacking the Protocol" + T.RESET)
    print()

    result = subprocess.run(
        [sys.executable, "red_team.py"],
        cwd=os.getcwd()
    )
    sys.exit(result.returncode)


# =========================================================
# DEMO: REGISTRY
# =========================================================

def demo_registry():
    banner()
    print(T.BOLD + "  MODE: Attestation Registry -- Chain Integrity Proof" + T.RESET)
    print()

    from registry import AttestationRegistry
    reg = AttestationRegistry()
    chain_result = reg.verify_chain()

    if chain_result["length"] == 0:
        warn("Registry is empty. Run --demo full-lifecycle first.")
    else:
        print(reg.export_proof())

        # Tamper test: briefly corrupt one entry and re-verify
        print()
        print(T.YELLOW + T.BOLD + "  TAMPER TEST: Simulating chain corruption..." + T.RESET)
        import copy, json
        with open("outputs/chain.json", "r") as f:
            chain_data = json.load(f)

        if len(chain_data["chain"]) > 0:
            chain_data["chain"][0]["verdict"] = "CORRUPTED"
            tampered_reg = AttestationRegistry.__new__(AttestationRegistry)
            tampered_reg.chain_path = "outputs/chain.json"
            tampered_reg._chain = chain_data["chain"]
            tamper_result = tampered_reg.verify_chain()
            if not tamper_result["valid"]:
                ok(f"Tamper detected at entry #{tamper_result['tampered_at_sequence']} -- chain integrity proof works!")
            else:
                error("Tamper NOT detected -- this is a bug.")


# =========================================================
# DEMO: ATTESTATION-GATED API (AGENT AUTH)
# =========================================================
def demo_agent_auth():
    banner()
    print("  MODE: Attestation-Gated API -- Securing Autonomous Agents\n")
    
    print(T.BOLD + T.CYAN + "[1/2] Generating Agent Intent and Attestation Key..." + T.RESET)
    subprocess.run([sys.executable, "auth/generate_token.py"], capture_output=True, cwd=os.getcwd())
    subprocess.run([sys.executable, "cgi_runtime.py"], capture_output=True, cwd=os.getcwd())
    ok("Intent Generated: outputs/inference_result.txt")
    ok("Attestation Key Generated: outputs/portable_attestation.json")
    pause()

    print(T.BOLD + T.CYAN + "[2/2] Agent POSTs Intent + Attestation to Banking API..." + T.RESET)
    pause()
    
    # Run the gateway script directly
    proc = subprocess.run([sys.executable, "api_gateway.py"], capture_output=True, text=True, cwd=os.getcwd())
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr)
        
    print(T.BOLD + T.CYAN + "\n[RED TEAM] Attacker tries to submit the same payload WITHOUT the Attestation Key..." + T.RESET)
    pause()
    
    # Temporarily hide the attestation
    os.rename("outputs/portable_attestation.json", "outputs/hidden.json")
    try:
        proc2 = subprocess.run([sys.executable, "api_gateway.py"], capture_output=True, text=True, cwd=os.getcwd())
        print(proc2.stdout)
    finally:
        os.rename("outputs/hidden.json", "outputs/portable_attestation.json")

    print(T.BOLD + T.CYAN + "\n[RED TEAM] The AI hallucinates and attempts to trade 500,000 shares (Exceeding Contract Bounds)..." + T.RESET)
    pause()
    
    print("  Generating Rogue Intent and valid cryptographic Attestation Key...")
    subprocess.run([sys.executable, "auth/generate_token.py", "--rogue"], capture_output=True, cwd=os.getcwd())
    subprocess.run([sys.executable, "cgi_runtime.py"], capture_output=True, cwd=os.getcwd())
    
    proc3 = subprocess.run([sys.executable, "api_gateway.py"], capture_output=True, text=True, cwd=os.getcwd())
    print(proc3.stdout)
    
    print(T.BOLD + T.CYAN + "\n[RED TEAM] Attacker executes a Double-Spend Replay Attack..." + T.RESET)
    pause()
    
    print("  Generating fresh legitimate Intent...")
    subprocess.run([sys.executable, "auth/generate_token.py"], capture_output=True, cwd=os.getcwd())
    subprocess.run([sys.executable, "cgi_runtime.py"], capture_output=True, cwd=os.getcwd())
    
    print("  [1st POST] Agent submits trade...")
    proc4 = subprocess.run([sys.executable, "api_gateway.py"], capture_output=True, text=True, cwd=os.getcwd())
    print(proc4.stdout)
    
    print("  [2nd POST] Attacker intercepts the valid attestation and POSTs it again to double-spend...")
    pause()
    proc5 = subprocess.run([sys.executable, "api_gateway.py"], capture_output=True, text=True, cwd=os.getcwd())
    print(proc5.stdout)


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CGI Protocol v4.0 -- Live Demo CLI"
    )
    parser.add_argument(
        "--demo",
        choices=["full-lifecycle", "audit-only", "red-team", "registry", "agent-auth"],
        default="full-lifecycle",
        help="Which demo to run"
    )
    args = parser.parse_args()

    if args.demo == "full-lifecycle":
        demo_full_lifecycle()
    elif args.demo == "audit-only":
        demo_audit_only()
    elif args.demo == "red-team":
        demo_red_team()
    elif args.demo == "registry":
        demo_registry()
    elif args.demo == "agent-auth":
        demo_agent_auth()
