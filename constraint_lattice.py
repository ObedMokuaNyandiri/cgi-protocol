"""
The Semantic Constraint Lattice — Sovereign Intelligence Protocol v11.0
=======================================================================

UPGRADED to v11.0: Embedding-Space Violation Detection.

This module is a transparent shim that re-exports the full v2 engine.
All existing callers (zkcot_engine, cgi_runtime, verifier, cgi_sdk) work
without any changes — the public API is fully preserved.

New in v11.0 (constraint_lattice_v2):
  - EmbeddingEngine: MiniLM-L6-v2 sentence encoder, lazy-loaded, 22MB
  - DualModeScanner: EMBEDDING cosine-similarity + LEXICAL pattern matching
  - ViolationEvidenceCertificate: forensic report for each violation
  - LatticeFingerprint: tamper-evident corpus commitment
  - Paraphrase-resistant: operates in 384-dim embedding space
  - Fail-closed: unavailable embeddings → LatticeUnavailableError

Severity Levels (unchanged):
  L0 (FATAL):    Immediate abort + Evidence-of-Misconduct proof generated.
  L1 (CRITICAL): Logged and escalated. Execution continues under scrutiny.
  L2 (WARNING):  Recorded. Informational quality signal.
"""

# ──────────────────────────────────────────────────────────────────────────────
# Transparent re-export from v2 — zero changes required in any caller
# ──────────────────────────────────────────────────────────────────────────────
from constraint_lattice_v2 import (                   # noqa: F401
    ViolationSeverity,
    ConstraintViolation,
    ViolationEvidenceCertificate,
    ConstraintLattice,
    LatticeUnavailableError,
    LATTICE_FINGERPRINT,
    FORBIDDEN_CONCEPT_CORPUS,
    EmbeddingEngine,
    DualModeScanner,
)

# Keep these available for any code that imported directly from this module
__all__ = [
    "ViolationSeverity",
    "ConstraintViolation",
    "ViolationEvidenceCertificate",
    "ConstraintLattice",
    "LatticeUnavailableError",
    "LATTICE_FINGERPRINT",
    "FORBIDDEN_CONCEPT_CORPUS",
    "EmbeddingEngine",
    "DualModeScanner",
]
