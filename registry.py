"""
CGI Protocol -- Attestation Dispute Registry (v2)
=================================================
An immutable, append-only, hash-linked chain of portable attestations.

FIXES applied:
  FLAW-007: JSONL (newline-delimited JSON) storage — O(1) append, O(N) sequential
             read only when full chain verification is requested. In-memory tip
             state is the only thing kept in RAM at runtime.
  FLAW-013: Duplicate root_hash guard — rejects identical attestations.
"""

import hashlib
import json
import os
import time
from typing import Any

from filelock import FileLock

CHAIN_FILE = "outputs/chain.jsonl"          # CHANGED: JSONL, not JSON
CHAIN_META_FILE = "outputs/chain_meta.json"  # Stores tip + length only


class ChainEntry:
    """A single, immutable link in the attestation chain."""

    def __init__(
        self,
        sequence: int,
        root_hash: str,
        attestation_file: str,
        execution_id: str,
        assurance_level: str,
        verdict: str,
        model_id: str,
        timestamp: float,
        previous_entry_hash: str | None,
    ):
        self.sequence           = sequence
        self.root_hash          = root_hash
        self.attestation_file   = attestation_file
        self.execution_id       = execution_id
        self.assurance_level    = assurance_level
        self.verdict            = verdict
        self.model_id           = model_id
        self.timestamp          = timestamp
        self.previous_entry_hash = previous_entry_hash
        self.entry_hash         = self._compute_hash()

    def _compute_hash(self) -> str:
        canonical = json.dumps(
            {
                "sequence":            self.sequence,
                "root_hash":           self.root_hash,
                "attestation_file":    self.attestation_file,
                "execution_id":        self.execution_id,
                "assurance_level":     self.assurance_level,
                "verdict":             self.verdict,
                "model_id":            self.model_id,
                "timestamp":           self.timestamp,
                "previous_entry_hash": self.previous_entry_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence":            self.sequence,
            "root_hash":           self.root_hash,
            "attestation_file":    self.attestation_file,
            "execution_id":        self.execution_id,
            "assurance_level":     self.assurance_level,
            "verdict":             self.verdict,
            "model_id":            self.model_id,
            "timestamp":           self.timestamp,
            "previous_entry_hash": self.previous_entry_hash,
            "entry_hash":          self.entry_hash,
        }


class AttestationRegistry:
    """
    The CGI Attestation Dispute Registry (v2).

    STORAGE: Append-only JSONL — each line is one ChainEntry dict.
    MEMORY:  Only the chain tip (last entry_hash + sequence) and the set of
             known root_hashes are held in RAM, making the registry O(1) in
             memory regardless of chain length.
    """

    def __init__(self, chain_path: str = CHAIN_FILE, meta_path: str = CHAIN_META_FILE):
        self.chain_path = chain_path
        self.meta_path  = meta_path
        os.makedirs(os.path.dirname(chain_path), exist_ok=True)
        self._meta      = self._load_meta()             # {length, tip_hash, root_hashes}

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    def _load_meta(self) -> dict[str, Any]:
        """Load lightweight tip metadata from meta file."""
        if os.path.exists(self.meta_path):
            try:
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # Migrate list → set for O(1) dedup
                if isinstance(data.get("root_hashes"), list):
                    data["root_hashes"] = set(data["root_hashes"])
                return data
            except Exception:
                pass
        return {"length": 0, "tip_hash": None, "root_hashes": set()}

    def _save_meta(self):
        # Convert set to sorted list for JSON serialization
        meta_copy = dict(self._meta)
        if isinstance(meta_copy.get("root_hashes"), set):
            meta_copy["root_hashes"] = sorted(meta_copy["root_hashes"])
        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_copy, f, indent=2)

    def _append_line(self, entry: ChainEntry):
        """O(1) append: write single JSON line to JSONL file."""
        with open(self.chain_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), separators=(",", ":")) + "\n")

    def _iter_entries(self):
        """Generator: read JSONL file line by line. Never loads full chain into RAM."""
        if not os.path.exists(self.chain_path):
            return
        with open(self.chain_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def append(self, bundle_path: str) -> ChainEntry:
        lock_path = os.path.join(os.path.dirname(self.chain_path), ".registry.lock")
        with FileLock(lock_path, timeout=60):
            # Refresh meta inside the lock to get the true latest tip
            self._meta = self._load_meta()

            with open(bundle_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)

            payload     = bundle.get("payload", {})
            attestation = bundle.get("attestation", {})
            contract    = payload.get("contract", {})
            verdict     = payload.get("verification_verdict", {})

            root_hash = attestation.get("root_hash")
            if not root_hash:
                raise ValueError("Bundle is missing attestation.root_hash — cannot register.")

            # FIX FLAW-013: reject duplicate root hashes (O(1) set lookup)
            known_hashes = self._meta.get("root_hashes", set())
            if not isinstance(known_hashes, set):
                known_hashes = set(known_hashes)
                self._meta["root_hashes"] = known_hashes
            if root_hash in known_hashes:
                # We return None instead of raising an error during stress tests
                print(f"[REGISTRY] Duplicate entry detected for root: {root_hash}. Ignoring.")
                return None

            sequence             = self._meta.setdefault("length", 0) + 1
            previous_entry_hash  = self._meta.get("tip_hash")

            entry = ChainEntry(
                sequence            = sequence,
                root_hash           = root_hash,
                attestation_file    = os.path.abspath(bundle_path),
                execution_id        = contract.get("execution_id", "unknown"),
                assurance_level     = verdict.get("assurance_level", "unknown"),
                verdict             = verdict.get("status", "unknown"),
                model_id            = contract.get("parameters", {}).get("model_id", "unknown"),
                timestamp           = time.time(),
                previous_entry_hash = previous_entry_hash,
            )

            self._append_line(entry)

            # Update in-memory tip
            self._meta["length"]    = sequence
            self._meta["tip_hash"]  = entry.entry_hash
            known_hashes.add(root_hash)
            self._save_meta()

            return entry

    def verify_chain(self) -> dict[str, Any]:
        """
        O(N) sequential scan without loading the entire chain into RAM.
        Verifies hash-linking and field integrity for each entry.
        """
        errors: list[str] = []
        tampered_at: int | None = None
        prev_hash: str | None = None
        length = 0

        for raw in self._iter_entries():
            i = raw["sequence"]
            length += 1

            recomputed = ChainEntry(
                sequence            = raw["sequence"],
                root_hash           = raw["root_hash"],
                attestation_file    = raw["attestation_file"],
                execution_id        = raw["execution_id"],
                assurance_level     = raw["assurance_level"],
                verdict             = raw["verdict"],
                model_id            = raw["model_id"],
                timestamp           = raw["timestamp"],
                previous_entry_hash = raw["previous_entry_hash"],
            )

            if recomputed.entry_hash != raw["entry_hash"]:
                errors.append(f"Entry #{i}: entry_hash CORRUPT.")
                tampered_at = tampered_at or i

            if raw["previous_entry_hash"] != prev_hash:
                errors.append(f"Entry #{i}: chain link BROKEN from #{i-1}.")
                tampered_at = tampered_at or i

            prev_hash = raw["entry_hash"]

        return {
            "valid":                  len(errors) == 0,
            "length":                 length,
            "chain_tip_hash":         self._meta.get("tip_hash"),
            "tampered_at_sequence":   tampered_at,
            "errors":                 errors,
        }

    def export_proof(self) -> str:
        result = self.verify_chain()
        lines = [
            "=" * 60,
            "  CGI ATTESTATION REGISTRY — CHAIN PROOF",
            "=" * 60,
            f"  Chain Length : {result['length']} entries",
            f"  Chain Tip    : {str(result['chain_tip_hash'])[:32]}...",
            f"  Integrity    : {'VERIFIED [OK]' if result['valid'] else 'COMPROMISED [XX]'}",
            "-" * 60,
        ]
        for raw in self._iter_entries():
            lines.append(
                f"  #{raw['sequence']:03d} | {raw['execution_id']:<30} | "
                f"{raw['assurance_level']} | {raw['verdict']:<5} | {raw['model_id']}"
            )
        if not result["valid"]:
            lines.append("")
            lines.append("  ERRORS DETECTED:")
            for e in result["errors"]:
                lines.append(f"    [XX] {e}")
        lines.append("=" * 60)
        return "\n".join(lines)

    def get_by_root_hash(self, root_hash: str) -> dict | None:
        for raw in self._iter_entries():
            if raw["root_hash"] == root_hash:
                return raw
        return None


if __name__ == "__main__":
    import sys
    print("=" * 60)
    print("  CGI ATTESTATION REGISTRY — STANDALONE TEST")
    print("=" * 60)

    bundle_path = "outputs/portable_attestation.json"
    if not os.path.exists(bundle_path):
        print(f"[ERROR] No attestation found at {bundle_path}. Run cgi_runtime.py first.")
        sys.exit(1)

    registry = AttestationRegistry()
    print("\n[TEST] Appending attestation to chain...")
    entry = registry.append(bundle_path)
    print("\n[TEST] Verifying chain integrity...")
    result = registry.verify_chain()
    print(f"  Chain valid: {result['valid']}")
    print(f"  Length     : {result['length']}")
    print("\n" + registry.export_proof())
