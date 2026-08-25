"""
CGI Protocol — Base Adapter Interface
======================================
All AI backend adapters inherit from BaseAdapter.
The uniform interface means the gateway is 100% decoupled from any
specific model provider; swapping backends requires only an env-var change.

Adapter Contract:
    generate(prompt, max_tokens, execution_id, seed) -> AdapterResult
    health_check()                                   -> bool (optional)
    list_models()                                    -> list[str] (optional)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("cgi.adapters.base")


@dataclass
class AdapterResult:
    """
    Structured result from any adapter's generate() call.
    Backward-compatible with the legacy tuple(text, stop_reason, token_count)
    via the `to_tuple()` helper used by the gateway.
    """
    text: str
    stop_reason: str = "stop"
    token_count: int = 0
    model_used: str = ""
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    # Raw response for debugging / forensics — not included in attestation bundle
    _raw: Optional[dict] = field(default=None, repr=False)

    def to_tuple(self) -> tuple[str, str, int]:
        """Legacy interface: (generated_text, stop_reason, token_count)."""
        return self.text, self.stop_reason, self.token_count


@dataclass
class AdapterCapabilities:
    """What features the adapter supports — used by the gateway for feature-gating."""
    supports_streaming: bool = False
    supports_seed: bool = False          # Can the model honour a fixed seed?
    supports_system_prompt: bool = True  # Can we inject a system prompt?
    supports_temperature: bool = True
    supports_token_count: bool = True    # Does the API return usage data?
    requires_local_model: bool = False   # True for subprocess / local models


class BaseAdapter:
    """
    Abstract base class for all CGI Protocol AI backend adapters.

    Minimal implementation:
        class MyAdapter(BaseAdapter):
            def generate(self, prompt, max_tokens, execution_id, seed) -> tuple[str, str, int]:
                ...

    Full implementation adds health_check() and list_models().
    """

    # Subclasses may override to declare capabilities
    capabilities: AdapterCapabilities = AdapterCapabilities()

    # ── Required ──────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        model_id: str,
        max_tokens: int,
        execution_id: str,
        seed: int,
    ) -> tuple[str, str, int]:
        """
        Run inference and return (generated_text, stop_reason, token_count).

        This signature is intentionally simple for backward compatibility.
        Adapters that want to return richer data should use AdapterResult internally
        and call .to_tuple() at the end.
        """
        raise NotImplementedError(
            f"{type(self).__name__} must implement generate()"
        )

    # ── Optional ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Ping the backend to verify it is reachable.
        Returns True if healthy, False otherwise.
        Default: always True (no-op).
        """
        return True

    def list_models(self) -> list[str]:
        """
        Return a list of model IDs available on this backend.
        Used by the /v1/models endpoint (future).
        Default: empty list (unsupported).
        """
        return []

    # ── Utility ───────────────────────────────────────────────

    @staticmethod
    def _measure(start: float) -> float:
        """Return elapsed ms since `start = time.monotonic()`."""
        return round((time.monotonic() - start) * 1000, 1)

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>"
