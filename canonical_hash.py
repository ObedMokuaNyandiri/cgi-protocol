"""
CGI Protocol -- Shared Canonical Hash Utility
=============================================
Single source of truth for the root hash computation.
Imported by BOTH cgi_runtime.py (prover) and verifier.py (verifier) to
eliminate the hash-divergence bug (FLAW-002).
"""
import hashlib
import json
from typing import Any


def hash_component(comp: Any) -> str:
    """SHA-256 of a canonically serialised (sort_keys) component."""
    return hashlib.sha256(
        json.dumps(comp, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def compute_canonical_root(payload: dict[str, Any]) -> str:
    """
    Derives the deterministic canonical root hash from a payload dict.

    Components (order is fixed and must never change):
        contract | runtime_state | runtime_identity | output_commitment |
        evidence | generation_summary | verification_verdict | deliberation
    """
    c_hash   = hash_component(payload.get("contract", {}))
    rs_hash  = hash_component(payload.get("runtime_state", {}))
    ri_hash  = hash_component(payload.get("runtime_identity", {}))
    oc_hash  = hash_component(payload.get("output_commitment", {}))
    ev_hash  = hash_component(payload.get("evidence", {}))
    gs_hash  = hash_component(payload.get("generation_summary", {}))
    vv_hash  = hash_component(payload.get("verification_verdict", {}))
    del_hash = hash_component(payload.get("deliberation", {}))

    root = hashlib.sha256(
        f"{c_hash}|{rs_hash}|{ri_hash}|{oc_hash}|{ev_hash}|{gs_hash}|{vv_hash}|{del_hash}"
        .encode()
    ).hexdigest()
    return root


def compute_component_hashes(payload: dict[str, Any]) -> dict[str, str]:
    """Returns a dict of all component hashes for inclusion in the attestation block."""
    return {
        "contract_hash":             hash_component(payload.get("contract", {})),
        "runtime_state_hash":        hash_component(payload.get("runtime_state", {})),
        "runtime_identity_hash":     hash_component(payload.get("runtime_identity", {})),
        "output_commitment_hash":    hash_component(payload.get("output_commitment", {})),
        "evidence_hash":             hash_component(payload.get("evidence", {})),
        "generation_summary_hash":   hash_component(payload.get("generation_summary", {})),
        "verification_verdict_hash": hash_component(payload.get("verification_verdict", {})),
        "deliberation_hash":         hash_component(payload.get("deliberation", {})),
    }
