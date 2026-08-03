"""
CGI Protocol — Hardened Audit Ledger v2.0
==========================================
HIPAA-aligned, zero-cost SQLite audit ledger with:
  - WAL mode for concurrent reads
  - Connection context manager (no leaks)
  - Data classification column for HIPAA
  - User ID and request ID columns for access control audit
  - Proper error handling (no silent swallowing)
  - Audit log export for compliance reporting
  - Database migration support
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("cgi.ledger")

# Schema version — bump this when adding new columns
_SCHEMA_VERSION = 2


class AuditLedger:
    """
    Production audit ledger backed by SQLite with WAL mode.

    Usage:
        ledger = AuditLedger("/path/to/audit_ledger.db")
        ledger.record_attestation(...)
        entries = ledger.export_audit_log(limit=100)
        ledger.close()
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self):
        """Context manager ensuring connections are always closed."""
        conn = sqlite3.connect(self._db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize schema with WAL mode and migration support."""
        with self._connect() as conn:
            cursor = conn.cursor()

            # Enable WAL mode for concurrent reads
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=5000")

            # Schema version tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            """)

            # Check current version
            cursor.execute("SELECT MAX(version) FROM schema_version")
            row = cursor.fetchone()
            current_version = row[0] if row[0] is not None else 0

            if current_version < 1:
                # Original schema
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS attestations (
                        execution_id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        root_hash TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        full_bundle TEXT NOT NULL
                    )
                """)
                cursor.execute(
                    "INSERT OR IGNORE INTO schema_version (version) VALUES (1)"
                )
                logger.info("Ledger schema v1 initialized")

            if current_version < 2:
                # Healthcare / HIPAA columns
                for col, col_type, default in [
                    ("request_id", "TEXT", "''"),
                    ("user_id", "TEXT", "''"),
                    ("data_classification", "TEXT", "'PUBLIC'"),
                ]:
                    try:
                        cursor.execute(
                            f"ALTER TABLE attestations ADD COLUMN {col} {col_type} DEFAULT {default}"
                        )
                    except sqlite3.OperationalError:
                        pass  # Column already exists

                # Index for audit queries
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_attestations_timestamp
                    ON attestations(timestamp)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_attestations_classification
                    ON attestations(data_classification)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_attestations_user
                    ON attestations(user_id)
                """)

                cursor.execute(
                    "INSERT OR IGNORE INTO schema_version (version) VALUES (2)"
                )
                logger.info("Ledger schema migrated to v2 (HIPAA columns)")

            conn.commit()

    def record_attestation(
        self,
        execution_id: str,
        root_hash: str,
        signature: str,
        bundle: dict,
        request_id: str = "",
        user_id: str = "",
        data_classification: str = "PUBLIC",
    ) -> bool:
        """
        Immutable append to the audit ledger.
        Returns True on success, False if duplicate (with warning logged).
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    INSERT INTO attestations
                        (execution_id, timestamp, root_hash, signature, full_bundle,
                         request_id, user_id, data_classification)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        time.time(),
                        root_hash,
                        signature,
                        json.dumps(bundle),
                        request_id,
                        user_id,
                        data_classification,
                    ),
                )
                conn.commit()
                logger.info(
                    "LEDGER_RECORD | exec_id=%s hash=%s user=%s classification=%s",
                    execution_id, root_hash[:16], user_id, data_classification,
                )
                return True
            except sqlite3.IntegrityError:
                logger.warning(
                    "LEDGER_DUPLICATE | exec_id=%s — already recorded, skipping",
                    execution_id,
                )
                return False

    def get_attestation(self, execution_id: str) -> dict | None:
        """Retrieve an attestation bundle by execution ID."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT full_bundle FROM attestations WHERE execution_id = ?",
                (execution_id,),
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None

    def export_audit_log(
        self,
        limit: int = 100,
        offset: int = 0,
        classification: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Export audit log entries for HIPAA compliance reporting.
        Returns metadata (no full bundles) to minimize data exposure.
        """
        with self._connect() as conn:
            cursor = conn.cursor()

            query = """
                SELECT execution_id, timestamp, root_hash, request_id,
                       user_id, data_classification
                FROM attestations
            """
            params: list = []

            if classification:
                query += " WHERE data_classification = ?"
                params.append(classification)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [
                {
                    "execution_id": row["execution_id"],
                    "timestamp": row["timestamp"],
                    "timestamp_iso": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(row["timestamp"])
                    ),
                    "root_hash": row["root_hash"],
                    "request_id": row["request_id"],
                    "user_id": row["user_id"],
                    "data_classification": row["data_classification"],
                }
                for row in rows
            ]

    def count(self, classification: str | None = None) -> int:
        """Count total attestations, optionally filtered by classification."""
        with self._connect() as conn:
            cursor = conn.cursor()
            if classification:
                cursor.execute(
                    "SELECT COUNT(*) FROM attestations WHERE data_classification = ?",
                    (classification,),
                )
            else:
                cursor.execute("SELECT COUNT(*) FROM attestations")
            return cursor.fetchone()[0]

    def close(self) -> None:
        """Explicit close — called during app shutdown."""
        logger.info("Ledger closed | total_records=%d", self.count())


# ─────────────────────────────────────────────────────────────
# Backward compatibility — module-level functions for old code
# ─────────────────────────────────────────────────────────────

_default_ledger: AuditLedger | None = None


def init_db(db_path: str | None = None) -> AuditLedger:
    """Legacy init function — creates the default ledger singleton."""
    global _default_ledger
    if db_path is None:
        from config import settings
        db_path = settings.DB_PATH
    _default_ledger = AuditLedger(db_path)
    return _default_ledger


def record_attestation(
    execution_id: str,
    root_hash: str,
    signature: str,
    bundle: dict,
    **kwargs,
) -> bool:
    """Legacy function — delegates to the default ledger."""
    global _default_ledger
    if _default_ledger is None:
        init_db()
    return _default_ledger.record_attestation(
        execution_id=execution_id,
        root_hash=root_hash,
        signature=signature,
        bundle=bundle,
        **kwargs,
    )


def get_attestation(execution_id: str) -> dict | None:
    """Legacy function — delegates to the default ledger."""
    global _default_ledger
    if _default_ledger is None:
        init_db()
    return _default_ledger.get_attestation(execution_id)


if __name__ == "__main__":
    from config import settings
    ledger = AuditLedger(settings.DB_PATH)
    print(f"[LEDGER] Initialized at: {settings.DB_PATH}")
    print(f"[LEDGER] Total records: {ledger.count()}")
    ledger.close()
