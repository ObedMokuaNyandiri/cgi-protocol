"""
CGI Protocol — Blockchain Anchoring Engine v1.0
=================================================
Zero-cost, immutable audit anchoring via OpenTimestamps + Bitcoin.

How it works:
  1. Reads all un-anchored CGI attestation records from the SQLite ledger
  2. Builds a Merkle Root from their cryptographic `root_hash` values
  3. Submits the Merkle Root to public OpenTimestamps calendar servers
     (run by Bitcoin Core contributors — permanently free, no account needed)
  4. Saves the `.ots` proof file locally for offline verification
  5. Marks the batch as anchored in the database

Domain-agnostic: works identically for healthcare, legal, financial,
government, insurance, media, or any enterprise AI deployment.

Cost: $0.00 — calendar servers absorb the Bitcoin transaction fee by
batching millions of users' hashes into one transaction per day.

Usage (called automatically by api_gateway.py on schedule):
    from blockchain_anchor import AnchorEngine
    engine = AnchorEngine(ledger)
    result = await engine.run_anchor_cycle()
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ledger import AuditLedger

logger = logging.getLogger("cgi.blockchain_anchor")


# ─────────────────────────────────────────────────────────────
# OpenTimestamps Calendar Client (pure stdlib — no pip install)
# ─────────────────────────────────────────────────────────────

_DEFAULT_CALENDARS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
]

_OTS_TIMEOUT = 15  # seconds per calendar server


def _submit_to_calendar(digest_bytes: bytes, calendar_url: str) -> bytes | None:
    """
    Submit a 32-byte SHA-256 digest to an OpenTimestamps calendar server.
    Returns the raw .ots proof bytes on success, or None on failure.

    Protocol:
      POST <calendar_url>/digest
      Content-Type: application/x-www-form-urlencoded
      Body: raw 32-byte digest (binary, NOT hex)

    The server responds with a partial .ots timestamp proof that will
    be upgraded to a full Bitcoin-anchored proof within ~6 hours
    once the Bitcoin block is mined.
    """
    url = f"{calendar_url.rstrip('/')}/digest"
    try:
        req = urllib.request.Request(
            url,
            data=digest_bytes,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/vnd.opentimestamps.v1",
                "User-Agent": "CGI-Protocol-AnchorEngine/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_OTS_TIMEOUT) as resp:
            proof_bytes = resp.read()
            logger.info(
                "OTS_SUBMIT_OK | calendar=%s size=%db",
                calendar_url.split("//")[1].split("/")[0],
                len(proof_bytes),
            )
            return proof_bytes
    except urllib.error.HTTPError as e:
        logger.warning("OTS_SUBMIT_FAIL | calendar=%s http=%d", calendar_url, e.code)
        return None
    except Exception as e:
        logger.warning("OTS_SUBMIT_FAIL | calendar=%s error=%s", calendar_url, str(e))
        return None


# ─────────────────────────────────────────────────────────────
# Merkle Root Builder (domain-agnostic, pure hashlib)
# ─────────────────────────────────────────────────────────────

def _build_merkle_root(leaf_hashes: list[str]) -> str:
    """
    Build a Merkle Root from a list of hex-encoded SHA-256 hashes.
    Uses the same algorithm as merkle.py (compatible) but optimized
    for the anchoring batch flow (no tree storage needed, just root).
    """
    if not leaf_hashes:
        return "0" * 64

    # FIX M-3: Use removeprefix("0x") not lstrip("0x").
    # lstrip strips ALL leading chars that are '0' or 'x', which silently
    # corrupts hashes like "0x000abc" -> "abc". removeprefix is exact.
    current = [h.removeprefix("0x").lower() for h in leaf_hashes]

    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            combined = (left + right).encode("utf-8")
            next_level.append(hashlib.sha256(combined).hexdigest())
        current = next_level

    return current[0]


# ─────────────────────────────────────────────────────────────
# Anchor Result Dataclass
# ─────────────────────────────────────────────────────────────

@dataclass
class AnchorResult:
    anchor_id: str
    merkle_root: str
    record_count: int
    ots_proof_path: str | None
    submitted_to: list[str]
    status: str           # "ANCHORED" | "PARTIAL" | "FAILED" | "SKIPPED"
    message: str


# ─────────────────────────────────────────────────────────────
# AnchorEngine
# ─────────────────────────────────────────────────────────────

class AnchorEngine:
    """
    Blockchain Anchoring Engine for the CGI-Protocol.

    Designed to be called on a schedule (e.g., every hour via asyncio
    background task in api_gateway.py). Fully idempotent — safe to
    call multiple times; will only anchor records not yet anchored.

    Zero external dependencies — uses only Python stdlib.
    """

    def __init__(
        self,
        ledger: "AuditLedger",
        anchor_dir: str = "outputs/anchor_proofs",
        calendar_urls: list[str] | None = None,
        min_batch_size: int = 1,
    ):
        self.ledger = ledger
        self.anchor_dir = anchor_dir
        self.calendar_urls = calendar_urls or _DEFAULT_CALENDARS
        self.min_batch_size = min_batch_size
        os.makedirs(self.anchor_dir, exist_ok=True)

    def run_anchor_cycle(self) -> AnchorResult:
        """
        Execute one full anchor cycle:
          1. Fetch un-anchored records
          2. Build Merkle Root
          3. Submit to OTS calendar servers
          4. Save proof file
          5. Update ledger

        Returns an AnchorResult describing what happened.
        """
        # ── 1. Gather un-anchored records ─────────────────────────
        records = self.ledger.get_unanchored_records()

        if len(records) < self.min_batch_size:
            logger.info(
                "ANCHOR_SKIP | unanchored=%d min_batch=%d",
                len(records), self.min_batch_size,
            )
            return AnchorResult(
                anchor_id="",
                merkle_root="",
                record_count=0,
                ots_proof_path=None,
                submitted_to=[],
                status="SKIPPED",
                message=f"Only {len(records)} un-anchored record(s) — below min batch size of {self.min_batch_size}.",
            )

        anchor_id = f"anchor-{uuid.uuid4().hex[:16]}"
        execution_ids = [r["execution_id"] for r in records]
        root_hashes = [r["root_hash"] for r in records]

        logger.info(
            "ANCHOR_START | anchor_id=%s records=%d",
            anchor_id, len(records),
        )

        # ── 2. Build Merkle Root ───────────────────────────────────
        merkle_root = _build_merkle_root(root_hashes)
        logger.info("ANCHOR_MERKLE | root=%s", merkle_root[:32])

        # ── 3. Submit to OpenTimestamps Calendar Servers ───────────
        digest_bytes = bytes.fromhex(merkle_root)
        submitted_to: list[str] = []
        proof_bytes: bytes | None = None

        for calendar_url in self.calendar_urls:
            result = _submit_to_calendar(digest_bytes, calendar_url)
            if result is not None:
                submitted_to.append(calendar_url)
                if proof_bytes is None:
                    proof_bytes = result  # Keep first successful proof

        # ── 4. Save .ots proof file ───────────────────────────────
        ots_proof_path: str | None = None
        if proof_bytes:
            ots_filename = f"{anchor_id}.ots"
            ots_proof_path = os.path.join(self.anchor_dir, ots_filename)
            with open(ots_proof_path, "wb") as f:
                f.write(proof_bytes)
            logger.info("ANCHOR_PROOF_SAVED | path=%s", ots_proof_path)

            # Also save a human-readable sidecar JSON for easy inspection
            sidecar = {
                "anchor_id": anchor_id,
                "merkle_root": merkle_root,
                "record_count": len(records),
                "anchored_at_iso": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                ),
                "submitted_to": submitted_to,
                "execution_ids": execution_ids,
                "ots_proof_file": ots_filename,
                "verification_instructions": (
                    "Install opentimestamps-client (`pip install opentimestamps-client`), "
                    f"then run: `ots verify {ots_filename}`"
                ),
            }
            sidecar_path = ots_proof_path.replace(".ots", ".json")
            with open(sidecar_path, "w", encoding="utf-8") as f:
                json.dump(sidecar, f, indent=2)

        # ── 5. Determine status ───────────────────────────────────
        if len(submitted_to) == len(self.calendar_urls):
            status = "ANCHORED"
            message = f"Successfully anchored {len(records)} records to {len(submitted_to)} OTS calendar servers."
        elif submitted_to:
            status = "PARTIAL"
            message = f"Partial anchor: reached {len(submitted_to)}/{len(self.calendar_urls)} calendar servers."
        else:
            status = "FAILED"
            message = "All OTS calendar servers unreachable. Records remain un-anchored and will be retried next cycle."

        # ── 6. Write anchor record + mark attestations ────────────
        self.ledger.write_anchor_record(
            anchor_id=anchor_id,
            merkle_root=merkle_root,
            record_count=len(records),
            ots_servers=submitted_to,
            ots_proof_path=ots_proof_path,
            status=status,
        )

        # Only mark records as anchored if we successfully reached at least one server
        if submitted_to:
            self.ledger.mark_records_anchored(execution_ids, anchor_id)

        logger.info(
            "ANCHOR_COMPLETE | anchor_id=%s status=%s servers=%d/%d records=%d",
            anchor_id, status, len(submitted_to), len(self.calendar_urls), len(records),
        )

        return AnchorResult(
            anchor_id=anchor_id,
            merkle_root=merkle_root,
            record_count=len(records),
            ots_proof_path=ots_proof_path,
            submitted_to=submitted_to,
            status=status,
            message=message,
        )
