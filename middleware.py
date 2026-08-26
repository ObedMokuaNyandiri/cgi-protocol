"""
CGI Protocol — Security Middleware
====================================
Production-grade middleware for API authentication, rate limiting,
request tracing, and security headers.

All middleware is standard ASGI — compatible with any FastAPI/Starlette app.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("cgi.middleware")


# ─────────────────────────────────────────────────────────────
# Structured JSON Logging (VAL-2)
# ─────────────────────────────────────────────────────────────

class JSONLogFormatter(logging.Formatter):
    """
    Emits each log record as a single-line JSON object.
    Compatible with Datadog, Grafana Loki, GCP Cloud Logging.

    Enable by setting LOG_FORMAT=json in .env.
    """

    # Fields that are standard LogRecord internals — excluded from the JSON output
    # to avoid cluttering structured logs with Python implementation details.
    _SKIP_FIELDS: frozenset = frozenset({
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "id", "levelname", "levelno", "lineno", "module",
        "msecs", "message", "msg", "name", "pathname", "process",
        "processName", "relativeCreated", "stack_info", "thread",
        "threadName", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        import json as _json
        import datetime as _dt
        # Build ISO-8601 timestamp with microseconds from the epoch float.
        # We cannot use self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ") because
        # %f is a datetime directive — time.strftime (used internally) rejects it.
        dt = _dt.datetime.fromtimestamp(record.created, tz=_dt.timezone.utc)
        timestamp = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"
        log_entry: dict = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            log_entry["stack"] = self.formatStack(record.stack_info)
        # Promote any extra fields passed via logger.info(..., extra={...})
        for key, val in record.__dict__.items():
            if key not in self._SKIP_FIELDS:
                log_entry[key] = val
        return _json.dumps(log_entry, default=str)


def configure_json_logging() -> None:
    """
    Replace the root logger's handler formatters with JSONLogFormatter.
    Safe to call multiple times; idempotent.
    """
    formatter = JSONLogFormatter()
    root = logging.getLogger()
    for handler in root.handlers:
        handler.setFormatter(formatter)
    logger.info("JSON structured logging enabled")


# ─────────────────────────────────────────────────────────────
# API Key Authentication
# ─────────────────────────────────────────────────────────────

class APIKeyStore:
    """
    Manages API keys from a JSON file.

    File format:
    {
        "keys": [
            {
                "key_id": "org-acme-prod",
                "key_hash": "<sha256 hex of the API key>",
                "scopes": ["infer", "audit"],
                "organization": "Acme Health",
                "tier": "ENTERPRISE",
                "active": true
            }
        ]
    }

    The 'tier' field binds a specific license tier to this API key.
    Valid values: TRIAL | STARTER | PROFESSIONAL | ENTERPRISE
    When absent, the server-level license tier applies.
    """

    def __init__(self, keys_file: str):
        self._keys: dict[str, dict] = {}  # key_hash -> metadata
        self._file = keys_file
        self._last_mtime: float = 0.0
        self._load()

    def _check_reload(self) -> None:
        """Check if the keys file was modified and reload if necessary."""
        if not self._file or not os.path.exists(self._file):
            return
        
        try:
            mtime = os.path.getmtime(self._file)
            if mtime > self._last_mtime:
                self._load()
                self._last_mtime = mtime
        except Exception as exc:
            pass

    def _load(self) -> None:
        if not self._file or not os.path.exists(self._file):
            logger.warning("No API keys file configured — authentication disabled")
            return
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("keys", []):
                if entry.get("active", True):
                    self._keys[entry["key_hash"]] = entry
            logger.info("Loaded %d active API keys", len(self._keys))
        except Exception as exc:
            logger.error("Failed to load API keys file %s: %s", self._file, exc)

    @property
    def is_enabled(self) -> bool:
        return len(self._keys) > 0

    def authenticate(self, raw_key: str) -> dict | None:
        """Returns key metadata if valid, None otherwise."""
        self._check_reload()
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        return self._keys.get(key_hash)

    @staticmethod
    def hash_key(raw_key: str) -> str:
        """Utility to hash a raw API key for storage."""
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Validates X-API-Key header against the key store.
    Skips authentication for health check and public key endpoints.
    """

    # CRIT-5 fix: /dashboard/export/csv removed from EXEMPT_PATHS.
    # It was previously exempt, so AuthMiddleware never ran on it and never set
    # request.state.api_key_scopes. The endpoint's own scope check then saw an
    # empty list and returned 403 for everyone — including authenticated callers.
    # Note: We keep the dashboard UI and read-only attestation endpoints public,
    # so anyone can view the ledger, but massive exports require 'audit' scope.
    EXEMPT_PATHS: set[str] = {
        "/health", "/v1/public-key", "/docs", "/openapi.json", "/redoc",
        "/v1/anchor/status", "/v1/license/activate", "/v1/license/status",
        "/dashboard", "/v1/attestations", "/v1/stream/attestations"
    }

    def __init__(self, app, key_store: APIKeyStore):
        super().__init__(app)
        self._store = key_store

    async def dispatch(self, request: Request, call_next) -> Response:
        # 2. Check Exempt Paths
        if (
            request.url.path in self.EXEMPT_PATHS 
            or request.url.path.startswith("/docs") 
            or request.url.path.startswith("/openapi.json")
            or request.url.path.startswith("/v1/attestation")
        ):
            return await call_next(request)

        if not self._store.is_enabled:
            # SECURITY FIX (C-2): When no API keys file is configured the system
            # MUST NOT silently open access to all callers. Returning 503 forces
            # operators to consciously configure authentication before traffic
            # can reach protected endpoints. This is "secure by default".
            return JSONResponse(
                status_code=503,
                content={
                    "detail": (
                        "Authentication is not configured. "
                        "Set API_KEYS_FILE and run 'python auth/keygen.py --api-key' "
                        "to create an API key before sending requests."
                    )
                },
            )

        api_key = request.headers.get("X-API-Key", "") or request.query_params.get("api_key", "")
        if not api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing X-API-Key header or api_key query parameter"},
            )

        meta = self._store.authenticate(api_key)
        if meta is None:
            logger.warning(
                "AUTH_REJECTED | path=%s ip=%s",
                request.url.path,
                request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid API key"},
            )

        # Attach key metadata to request state for downstream use
        request.state.api_key_id     = meta.get("key_id", "unknown")
        request.state.api_key_org    = meta.get("organization", "unknown")
        request.state.api_key_scopes = meta.get("scopes", [])
        # Per-key license tier — enables multi-tenant tier enforcement.
        # If a key has no explicit tier, downstream uses the server-level license.
        request.state.api_key_tier   = meta.get("tier", None)

        return await call_next(request)


# ─────────────────────────────────────────────────────────────
# Rate Limiting (Sliding Window)
# ─────────────────────────────────────────────────────────────

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforces per-key (or per-IP) rate limiting backed by SQLite."""

    EXEMPT_PATHS: set[str] = {"/health", "/v1/public-key", "/docs", "/openapi.json", "/redoc", "/v1/license/status", "/v1/license/activate", "/v1/anchor/status"}

    def __init__(self, app, max_requests: int | Callable[[], int] = 30, window_seconds: int = 60):
        super().__init__(app)
        self._max = max_requests
        self._window = window_seconds

    @property
    def max_requests(self) -> int:
        if callable(self._max):
            return self._max()
        return self._max

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Use API key ID if authenticated, otherwise use client IP
        identity = getattr(request.state, "api_key_id", None)
        if not identity:
            identity = request.client.host if request.client else "unknown"

        ledger = getattr(request.app.state, "audit_ledger", None)
        limit = self.max_requests
        
        # If ledger is available, use database rate limiting (Fix Blocker #4)
        if ledger:
            allowed = ledger.check_rate_limit(identity, self._window, limit)
        else:
            # Fallback (e.g. during very early boot/tests before ledger is attached)
            allowed = True

        if not allowed:
            logger.warning(
                "RATE_LIMITED | identity=%s path=%s limit=%d/min",
                identity,
                request.url.path,
                limit
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded ({limit}/min). Try again later.",
                },
                headers={"Retry-After": str(self._window)},
            )

        return await call_next(request)


# ─────────────────────────────────────────────────────────────
# Request ID Tracing
# ─────────────────────────────────────────────────────────────

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Injects a unique X-Request-ID into every request and response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ─────────────────────────────────────────────────────────────
# Security Headers
# ─────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard security headers to all responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response
