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

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("cgi.middleware")


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
                "active": true
            }
        ]
    }
    """

    def __init__(self, keys_file: str):
        self._keys: dict[str, dict] = {}  # key_hash -> metadata
        self._file = keys_file
        self._load()

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

    EXEMPT_PATHS: set[str] = {"/health", "/v1/public-key", "/docs", "/openapi.json", "/redoc", "/dashboard", "/dashboard/export/csv", "/v1/stream/attestations", "/v1/anchor/status", "/v1/anchor/trigger"}

    def __init__(self, app, key_store: APIKeyStore):
        super().__init__(app)
        self._store = key_store

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self.EXEMPT_PATHS or request.url.path.startswith("/v1/attestation/"):
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

        api_key = request.headers.get("X-API-Key", "")
        if not api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing X-API-Key header"},
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
        request.state.api_key_id = meta.get("key_id", "unknown")
        request.state.api_key_org = meta.get("organization", "unknown")
        request.state.api_key_scopes = meta.get("scopes", [])

        return await call_next(request)


# ─────────────────────────────────────────────────────────────
# Rate Limiting (Sliding Window)
# ─────────────────────────────────────────────────────────────

from typing import Callable

class RateLimiter:
    """In-memory sliding window rate limiter. Per-key or per-IP.

    FIX H-7: Periodic bucket pruning prevents the _buckets dict from growing
    unboundedly across long-running processes. Every `_PRUNE_INTERVAL` calls
    to `is_allowed()` the method sweeps out identities whose windows are
    completely empty, reclaiming memory. The amortised cost is O(1) per call.
    """

    _PRUNE_INTERVAL = 1000  # prune dead buckets every N is_allowed() calls

    def __init__(self, max_requests: int | Callable[[], int] = 30, window_seconds: int = 60):
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._call_count = 0

    def _prune(self, now: float) -> None:
        """Remove entries for identities that have no events in the current window."""
        cutoff = now - self._window
        dead = [k for k, v in self._buckets.items() if not v or v[-1] <= cutoff]
        for k in dead:
            del self._buckets[k]

    def is_allowed(self, identity: str) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        bucket = self._buckets[identity]

        # Purge expired entries for this identity
        self._buckets[identity] = [t for t in bucket if t > cutoff]
        bucket = self._buckets[identity]

        limit = self.max_requests
        if len(bucket) >= limit:
            return False

        bucket.append(now)

        # Amortised global prune (H-7 memory leak fix)
        self._call_count += 1
        if self._call_count % self._PRUNE_INTERVAL == 0:
            self._prune(now)

        return True

    @property
    def max_requests(self) -> int:
        if callable(self._max):
            return self._max()
        return self._max


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforces per-key (or per-IP) rate limiting."""

    EXEMPT_PATHS: set[str] = {"/health", "/v1/public-key", "/docs", "/openapi.json", "/redoc", "/v1/license/status", "/v1/anchor/status", "/v1/stream/attestations", "/dashboard"}

    def __init__(self, app, limiter: RateLimiter):
        super().__init__(app)
        self._limiter = limiter

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Use API key ID if authenticated, otherwise use client IP
        identity = getattr(request.state, "api_key_id", None)
        if not identity:
            identity = request.client.host if request.client else "unknown"

        if not self._limiter.is_allowed(identity):
            limit = self._limiter.max_requests
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
                headers={"Retry-After": "60"},
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
