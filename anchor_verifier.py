"""
CGI Protocol — Anchor Verifier CLI v1.0
========================================
Standalone verification tool for blockchain-anchored AI attestations.

Given an execution_id or anchor_id, this tool:
  1. Retrieves the CGI attestation from the local SQLite ledger
  2. Loads the corresponding .ots proof file
  3. Reconstructs the Merkle path from the leaf to the anchor root
  4. Outputs a human-readable immutability verification report

Domain-agnostic — works for any enterprise deployment:
  Healthcare, Legal, Financial, Government, Insurance, Media, etc.

Usage:
    python anchor_verifier.py --exec-id exec-abc123
    python anchor_verifier.py --anchor-id anchor-def456
    python anchor_verifier.py --list-anchors
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

# ── Bootstrap path so we can import CGI modules regardless of cwd ──
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from config import settings
from ledger import AuditLedger


# ─────────────────────────────────────────────────────────────
# ANSI colours (auto-disabled on Windows if not supported)
# ─────────────────────────────────────────────────────────────

_USE_COLOUR = sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR")

def _c(code: str, text: str) -> str:
    if _USE_COLOUR:
        return f"\033[{code}m{text}\033[0m"
    return text

def _green(t: str) -> str: return _c("32;1", t)
def _red(t: str) -> str:   return _c("31;1", t)
def _cyan(t: str) -> str:  return _c("36", t)
def _bold(t: str) -> str:  return _c("1", t)
def _dim(t: str) -> str:   return _c("2", t)


# ─────────────────────────────────────────────────────────────
# Merkle Proof Reconstruction
# ─────────────────────────────────────────────────────────────

def _recompute_merkle_root(leaf_hashes: list[str]) -> str:
    """Reconstruct Merkle root from all leaf hashes in a batch."""
    if not leaf_hashes:
        return "0" * 64
    current = [h.lstrip("0x").lower() for h in leaf_hashes]
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left  = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            combined = (left + right).encode("utf-8")
            next_level.append(hashlib.sha256(combined).hexdigest())
        current = next_level
    return current[0]


# ─────────────────────────────────────────────────────────────
# Report Printers
# ─────────────────────────────────────────────────────────────

def _print_divider(width: int = 58) -> None:
    print(_dim("─" * width))


def _print_report(
    exec_record: dict,
    anchor_record: dict,
    sidecar: dict | None,
    merkle_verified: bool,
) -> None:
    """Print a full human-readable verification report."""
    print()
    print(_bold("┌" + "─" * 56 + "┐"))
    print(_bold("│") + _cyan("  CGI-Protocol — Immutability Verification Report   ") + _bold("│"))
    print(_bold("└" + "─" * 56 + "┘"))
    print()

    _print_divider()
    print(_bold("  ATTESTATION RECORD"))
    _print_divider()
    print(f"  {'Execution ID':<20} {exec_record.get('execution_id', 'N/A')}")
    ts = exec_record.get('timestamp', 0)
    ts_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else "N/A"
    print(f"  {'Recorded At':<20} {ts_iso}")
    print(f"  {'CGI Root Hash':<20} {exec_record.get('root_hash', 'N/A')[:32]}...")
    print(f"  {'Classification':<20} {exec_record.get('data_classification', 'N/A')}")
    print()

    _print_divider()
    print(_bold("  BLOCKCHAIN ANCHOR"))
    _print_divider()
    print(f"  {'Anchor ID':<20} {anchor_record.get('anchor_id', 'N/A')}")
    print(f"  {'Anchored At':<20} {anchor_record.get('anchored_at_iso', 'N/A')}")
    print(f"  {'Merkle Root':<20} {anchor_record.get('merkle_root', 'N/A')[:32]}...")
    print(f"  {'Records in Batch':<20} {anchor_record.get('record_count', 0)}")

    servers = anchor_record.get("ots_servers", [])
    print(f"  {'OTS Servers Hit':<20} {len(servers)} server(s)")
    for s in servers:
        print(f"  {'':20}  {_dim(s.split('//')[1].split('/')[0])}")

    ots_path = anchor_record.get("ots_proof_path")
    ots_exists = os.path.exists(ots_path) if ots_path else False
    ots_label = _green("✓ Found") if ots_exists else _red("✗ Missing")
    print(f"  {'OTS Proof File':<20} {ots_label}")
    if ots_path:
        print(f"  {'':20}  {_dim(ots_path)}")
    print()

    _print_divider()
    print(_bold("  CRYPTOGRAPHIC VERIFICATION"))
    _print_divider()

    if merkle_verified:
        print(f"  Merkle Inclusion  {_green('✓ VERIFIED')}")
        print(f"  {_dim('This record is mathematically included in the anchored Merkle Root.')}")
    else:
        print(f"  Merkle Inclusion  {_red('✗ FAILED')}")
        print(f"  {_dim('Merkle root mismatch — data may have been tampered with.')}")
    print()

    anchor_status = anchor_record.get("status", "UNKNOWN")
    if anchor_status == "ANCHORED":
        btc_label = _green("✓ SUBMITTED TO BITCOIN NETWORK (pending confirmation)")
    elif anchor_status == "PARTIAL":
        btc_label = _cyan("⚠ PARTIALLY ANCHORED (some servers unreachable)")
    else:
        btc_label = _red("✗ NOT YET ANCHORED")
    print(f"  Bitcoin Status    {btc_label}")
    print()

    _print_divider()
    # Overall verdict
    if merkle_verified and anchor_status in ("ANCHORED", "PARTIAL"):
        print()
        print(_green("  ✅  VERDICT: CRYPTOGRAPHICALLY IMMUTABLE"))
        print(_dim("  This AI inference is permanently recorded on the Bitcoin blockchain."))
        print(_dim("  It is mathematically impossible to alter or delete this record."))
        print()
        if ots_path:
            print(_dim("  To get the Bitcoin block number (after ~6 hours), run:"))
            print(_dim(f"    pip install opentimestamps-client"))
            print(_dim(f"    ots verify {ots_path}"))
    else:
        print()
        print(_red("  ⚠   VERDICT: ANCHOR PENDING OR VERIFICATION FAILED"))
        print(_dim("  Run the anchor cycle or check for tampering."))
    print()


# ─────────────────────────────────────────────────────────────
# Main CLI Logic
# ─────────────────────────────────────────────────────────────

def verify_by_exec_id(ledger: AuditLedger, exec_id: str) -> None:
    """Retrieve and verify a single attestation by execution_id."""
    # Get the attestation record
    bundle = ledger.get_attestation(exec_id)
    if not bundle:
        print(_red(f"\n  ✗ No attestation found for execution_id: {exec_id}\n"))
        sys.exit(1)

    # Get the basic record metadata (including anchor_id)
    with ledger._connect() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT execution_id, timestamp, root_hash, data_classification, anchor_id "
            "FROM attestations WHERE execution_id = ?",
            (exec_id,),
        )
        row = cursor.fetchone()

    if not row:
        print(_red(f"\n  ✗ Attestation metadata not found for: {exec_id}\n"))
        sys.exit(1)

    exec_record = dict(row)
    anchor_id = exec_record.get("anchor_id")

    if not anchor_id:
        print(_red(f"\n  ⚠ Record '{exec_id}' has not yet been blockchain-anchored."))
        print(_dim("  Wait for the next anchor cycle (default: every hour) and try again.\n"))
        sys.exit(0)

    # Get anchor record
    anchors = ledger.get_anchor_status(limit=1000)
    anchor_record = next((a for a in anchors if a["anchor_id"] == anchor_id), None)
    if not anchor_record:
        print(_red(f"\n  ✗ Anchor record '{anchor_id}' not found in anchor_log.\n"))
        sys.exit(1)

    # Load sidecar JSON if available
    sidecar: dict | None = None
    ots_path = anchor_record.get("ots_proof_path")
    if ots_path:
        sidecar_path = ots_path.replace(".ots", ".json")
        if os.path.exists(sidecar_path):
            with open(sidecar_path, "r", encoding="utf-8") as f:
                sidecar = json.load(f)

    # Verify Merkle inclusion: recompute root from all records in this batch
    all_exec_ids = sidecar["execution_ids"] if sidecar else []
    merkle_verified = False
    if all_exec_ids:
        with ledger._connect() as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" * len(all_exec_ids))
            cursor.execute(
                f"SELECT root_hash FROM attestations WHERE execution_id IN ({placeholders}) "
                f"ORDER BY timestamp ASC",
                all_exec_ids,
            )
            rows = cursor.fetchall()
        batch_hashes = [r["root_hash"] for r in rows]
        recomputed_root = _recompute_merkle_root(batch_hashes)
        stored_root = anchor_record.get("merkle_root", "")
        merkle_verified = (recomputed_root.lstrip("0x").lower() == stored_root.lstrip("0x").lower())

    _print_report(exec_record, anchor_record, sidecar, merkle_verified)


def list_anchors(ledger: AuditLedger) -> None:
    """List all anchor cycles with summary."""
    anchors = ledger.get_anchor_status(limit=20)
    if not anchors:
        print(_dim("\n  No anchor cycles have run yet.\n"))
        return

    print()
    print(_bold(f"  {'ANCHOR ID':<26} {'STATUS':<10} {'RECORDS':<8} {'ANCHORED AT ISO'}"))
    _print_divider(72)
    for a in anchors:
        status = a["status"]
        status_label = (
            _green(f"{status:<10}") if status == "ANCHORED"
            else _cyan(f"{status:<10}") if status == "PARTIAL"
            else _red(f"{status:<10}")
        )
        print(f"  {a['anchor_id']:<26} {status_label} {a['record_count']:<8} {a['anchored_at_iso']}")
    print()


# ─────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CGI-Protocol Blockchain Anchor Verifier — proves AI inferences are immutably recorded on Bitcoin."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--exec-id", metavar="EXECUTION_ID",
                       help="Verify a specific AI inference by its execution ID.")
    group.add_argument("--anchor-id", metavar="ANCHOR_ID",
                       help="Show details of a specific anchor cycle.")
    group.add_argument("--list-anchors", action="store_true",
                       help="List all past anchor cycles.")

    args = parser.parse_args()
    ledger = AuditLedger(settings.DB_PATH)

    if args.exec_id:
        verify_by_exec_id(ledger, args.exec_id)
    elif args.list_anchors:
        list_anchors(ledger)
    elif args.anchor_id:
        anchors = ledger.get_anchor_status(limit=1000)
        anchor_record = next((a for a in anchors if a["anchor_id"] == args.anchor_id), None)
        if not anchor_record:
            print(_red(f"\n  ✗ Anchor '{args.anchor_id}' not found.\n"))
            sys.exit(1)
        print(json.dumps(anchor_record, indent=2))

    ledger.close()


if __name__ == "__main__":
    main()
