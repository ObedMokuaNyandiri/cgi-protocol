"""
CGI Protocol — Hardened Audit Ledger v2.0
==========================================
Enterprise-aligned, zero-cost SQLite audit ledger with:
  - WAL mode for concurrent reads
  - Connection context manager (no leaks)
  - Data classification column for audit security
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
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator

logger = logging.getLogger("cgi.ledger")

# Schema version — bump this when adding new columns
_SCHEMA_VERSION = 5


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
        # FIX H-5: os.path.dirname() returns "" for bare filenames (e.g. "audit.db").
        # os.makedirs("") raises FileNotFoundError, crashing the ledger at boot.
        d = os.path.dirname(db_path)
        if d:
            os.makedirs(d, exist_ok=True)
        # VAL-1: Thread-local store for per-thread cached connections.
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """
        Return a cached per-thread SQLite connection (VAL-1: connection pooling).
        One long-lived connection per thread eliminates open/close overhead on
        every DB call while remaining safe because SQLite connections are not
        shared across threads.
        """
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def _connect(self):
        """Context manager yielding the per-thread cached connection (VAL-1)."""
        conn = self._get_conn()
        try:
            yield conn
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise

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
                # Audit / Security columns
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
                logger.info("Ledger schema migrated to v2 (Security columns)")

            if current_version < 3:
                # Blockchain anchoring support
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS anchor_log (
                        anchor_id       TEXT PRIMARY KEY,
                        anchored_at     REAL NOT NULL,
                        merkle_root     TEXT NOT NULL,
                        record_count    INTEGER NOT NULL,
                        ots_servers     TEXT NOT NULL,
                        ots_proof_path  TEXT,
                        status          TEXT NOT NULL DEFAULT 'PENDING'
                    )
                """)
                # Column to track which attestations have been anchored
                try:
                    cursor.execute(
                        "ALTER TABLE attestations ADD COLUMN anchor_id TEXT DEFAULT NULL"
                    )
                except sqlite3.OperationalError:
                    pass  # Column already exists
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_attestations_anchor "
                    "ON attestations(anchor_id)"
                )
                cursor.execute(
                    "INSERT OR IGNORE INTO schema_version (version) VALUES (3)"
                )
                logger.info("Ledger schema migrated to v3 (Blockchain Anchor columns)")

            if current_version < 4:
                # CRIT-1: Persistent Merkle leaf hashes — chain survives restarts with no cap.
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS merkle_leaves (
                        id         INTEGER PRIMARY KEY AUTOINCREMENT,
                        leaf_hash  TEXT NOT NULL,
                        added_at   REAL NOT NULL
                    )
                """)
                # CRIT-3: Persistent replay cache — replay protection survives restarts.
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS replay_cache (
                        execution_id  TEXT PRIMARY KEY,
                        seen_at       REAL NOT NULL
                    )
                """)
                cursor.execute(
                    "INSERT OR IGNORE INTO schema_version (version) VALUES (4)"
                )
                logger.info("Ledger schema migrated to v4 (Merkle persistence + Replay cache)")

            if current_version < 5:
                # Fix Blocker #4: Persistent rate limiter state — survives restarts and works with multiple API_WORKERS.
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS rate_limit_cache (
                        id        INTEGER PRIMARY KEY AUTOINCREMENT,
                        identity  TEXT NOT NULL,
                        timestamp REAL NOT NULL
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_identity ON rate_limit_cache(identity, timestamp)")
                cursor.execute(
                    "INSERT OR IGNORE INTO schema_version (version) VALUES (5)"
                )
                logger.info("Ledger schema migrated to v5 (Rate Limit cache)")

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

    def get_anchor_proof_path(self, execution_id: str) -> str | None:
        """Retrieve the file path of the OTS anchor proof for an execution ID."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT l.ots_proof_path
                FROM attestations a
                JOIN anchor_log l ON a.anchor_id = l.anchor_id
                WHERE a.execution_id = ? AND l.ots_proof_path IS NOT NULL
                ''',
                (execution_id,),
            )
            row = cursor.fetchone()
            if row:
                return row[0]
            return None

    def export_audit_log(
        self,
        limit: int = 100,
        offset: int = 0,
        classification: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Export audit log entries for compliance reporting.
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

    def export_audit_log_stream(self, since_timestamp: float | None = None) -> Iterator[dict[str, Any]]:
        """
        Generator that yields audit log entries one by one for streaming.
        Handles millions of records without OOM.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            query = """
                SELECT execution_id, timestamp, root_hash, request_id,
                       user_id, data_classification, anchor_id
                FROM attestations
            """
            params = []
            if since_timestamp is not None:
                query += " WHERE timestamp >= ?"
                params.append(since_timestamp)
                
            query += " ORDER BY timestamp DESC"
            
            cursor.execute(query, tuple(params))
            while True:
                rows = cursor.fetchmany(1000)
                if not rows:
                    break
                for row in rows:
                    yield {
                        "execution_id": row["execution_id"],
                        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(row["timestamp"])),
                        "root_hash": row["root_hash"],
                        "request_id": row["request_id"],
                        "user_id": row["user_id"],
                        "data_classification": row["data_classification"],
                        "anchor_id": row["anchor_id"],
                    }
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

    # ──────────────────────────────────────────────────────────────
    # Blockchain Anchoring Methods (Schema v3)
    # ──────────────────────────────────────────────────────────────

    def get_unanchored_records(self) -> list[dict]:
        """Return all attestation records that have not yet been blockchain-anchored."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT execution_id, timestamp, root_hash "
                "FROM attestations WHERE anchor_id IS NULL "
                "ORDER BY timestamp ASC"
            )
            rows = cursor.fetchall()
            return [
                {
                    "execution_id": row["execution_id"],
                    "timestamp": row["timestamp"],
                    "root_hash": row["root_hash"],
                }
                for row in rows
            ]

    def mark_records_anchored(self, execution_ids: list[str], anchor_id: str) -> int:
        """Mark a batch of attestations as anchored. Returns count updated."""
        if not execution_ids:
            return 0
        with self._connect() as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" * len(execution_ids))
            cursor.execute(
                f"UPDATE attestations SET anchor_id = ? "
                f"WHERE execution_id IN ({placeholders})",
                [anchor_id] + execution_ids,
            )
            conn.commit()
            updated = cursor.rowcount
            logger.info("ANCHOR_MARKED | anchor_id=%s records=%d", anchor_id, updated)
            return updated

    def write_anchor_record(
        self,
        anchor_id: str,
        merkle_root: str,
        record_count: int,
        ots_servers: list[str],
        ots_proof_path: str | None = None,
        status: str = "PENDING",
    ) -> None:
        """Write a new anchor cycle result to the anchor_log table."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO anchor_log
                    (anchor_id, anchored_at, merkle_root, record_count,
                     ots_servers, ots_proof_path, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    anchor_id,
                    time.time(),
                    merkle_root,
                    record_count,
                    json.dumps(ots_servers),
                    ots_proof_path,
                    status,
                ),
            )
            conn.commit()
            logger.info(
                "ANCHOR_RECORD | anchor_id=%s root=%s records=%d status=%s",
                anchor_id, merkle_root[:16], record_count, status,
            )

    def get_anchor_status(self, limit: int = 10) -> list[dict]:
        """Return recent anchor cycle records for the /v1/anchor/status endpoint."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT anchor_id, anchored_at, merkle_root, record_count, "
                "ots_servers, ots_proof_path, status "
                "FROM anchor_log ORDER BY anchored_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "anchor_id": row["anchor_id"],
                    "anchored_at": row["anchored_at"],
                    "anchored_at_iso": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(row["anchored_at"])
                    ),
                    "merkle_root": row["merkle_root"],
                    "record_count": row["record_count"],
                    "ots_servers": json.loads(row["ots_servers"]),
                    "ots_proof_path": row["ots_proof_path"],
                    "status": row["status"],
                }
                for row in rows
            ]

    # ──────────────────────────────────────────────────────────────
    # Merkle Leaf Persistence (Schema v4 — CRIT-1 fix)
    # ──────────────────────────────────────────────────────────────

    def append_merkle_leaf(self, leaf_hash: str) -> None:
        """Persist a Merkle leaf hash so the chain survives container restarts."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO merkle_leaves (leaf_hash, added_at) VALUES (?, ?)",
                (leaf_hash, time.time()),
            )
            conn.commit()

    def load_merkle_leaves(self) -> list[str]:
        """
        Load all persisted Merkle leaf hashes in insertion order.
        No cap — replaces the old export_audit_log(limit=10000) reconstruction
        which permanently broke the chain after 10,000 records.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT leaf_hash FROM merkle_leaves ORDER BY id ASC"
            )
            return [row[0] for row in cursor.fetchall()]

    # ──────────────────────────────────────────────────────────────
    # Replay Cache Persistence (Schema v4 — CRIT-3 fix)
    # ──────────────────────────────────────────────────────────────

    def persist_replay_id(self, execution_id: str) -> None:
        """Persist an execution ID so replay protection survives restarts."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO replay_cache (execution_id, seen_at) VALUES (?, ?)",
                (execution_id, time.time()),
            )
            conn.commit()

    def prune_old_replay_ids(self, ttl_seconds: int = 3600) -> None:
        """Removes replay cache entries older than ttl_seconds."""
        cutoff = time.time() - ttl_seconds
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM replay_cache WHERE seen_at <= ?", (cutoff,))
            conn.commit()

    def check_rate_limit(self, identity: str, window_seconds: int, max_requests: int) -> bool:
        """
        Fix Blocker #4: Database-backed rate limiter.
        Checks if `identity` has exceeded `max_requests` in the last `window_seconds`.
        Returns True if allowed, False if blocked.
        Automatically prunes old entries for this identity to bound table size.
        """
        now = time.time()
        cutoff = now - window_seconds
        with self._connect() as conn:
            cursor = conn.cursor()
            
            # Prune expired entries for this identity
            cursor.execute("DELETE FROM rate_limit_cache WHERE identity = ? AND timestamp <= ?", (identity, cutoff))
            
            # Count remaining valid entries
            cursor.execute("SELECT COUNT(*) FROM rate_limit_cache WHERE identity = ?", (identity,))
            count = cursor.fetchone()[0]
            
            if count >= max_requests:
                conn.commit()
                return False
                
            # Allow and record the new request
            cursor.execute("INSERT INTO rate_limit_cache (identity, timestamp) VALUES (?, ?)", (identity, now))
            conn.commit()
            return True

    def load_active_replay_ids(self, ttl_seconds: int = 3600) -> list[tuple[str, float]]:
        """Load replay IDs seen within the TTL window (default 1 hour)."""
        cutoff = time.time() - ttl_seconds
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT execution_id, seen_at FROM replay_cache "
                "WHERE seen_at > ? ORDER BY seen_at ASC",
                (cutoff,),
            )
            return [(row[0], row[1]) for row in cursor.fetchall()]

    def close(self) -> None:
        """Explicit close — called during app shutdown."""
        count = self.count()  # read before closing the connection
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None
        logger.info("Ledger closed | total_records=%d", count)


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
        _default_ledger = init_db()
    assert _default_ledger is not None
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
        _default_ledger = init_db()
    assert _default_ledger is not None
    return _default_ledger.get_attestation(execution_id)


if __name__ == "__main__":
    from config import settings
    ledger = AuditLedger(settings.DB_PATH)
    print(f"[LEDGER] Initialized at: {settings.DB_PATH}")
    print(f"[LEDGER] Total records: {ledger.count()}")
    ledger.close()
