"""
CGI Protocol — Anthropic Claude Adapter
=========================================
Connects to Anthropic's Messages API (Claude 3/4 family).

Configuration (via .env or environment):
    AI_BACKEND_TYPE   = anthropic
    AI_API_KEY        = sk-ant-...            (Anthropic API key)
    MODEL_ID          = claude-sonnet-4-5     (or any Claude model)
    AI_SYSTEM_PROMPT  = (optional)

Supported models:
    claude-opus-4-5, claude-sonnet-4-5, claude-haiku-3-5,
    claude-3-opus-20240229, claude-3-5-sonnet-20241022,
    claude-3-5-haiku-20241022

Docs: https://docs.anthropic.com/en/api/messages
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Tuple

from config import settings
from adapters.base import BaseAdapter, AdapterCapabilities

logger = logging.getLogger("cgi.adapters.anthropic")

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MODEL = "claude-sonnet-4-5"
_DEFAULT_SYSTEM = (
    "You are a controlled inference engine operating under cryptographic governance. "
    "Answer concisely and with technical precision."
)


class AnthropicClaudeAdapter(BaseAdapter):
    """
    Calls Anthropic's native Messages API.
    No SDK required — uses stdlib urllib.
    """

    capabilities = AdapterCapabilities(
        supports_streaming=False,
        supports_seed=False,          # Anthropic does not support deterministic seeds
        supports_system_prompt=True,  # Native first-class support
        supports_temperature=True,
        supports_token_count=True,
    )

    def __init__(self) -> None:
        self._api_key = settings.AI_API_KEY
        self._model_id = settings.MODEL_ID or _DEFAULT_MODEL
        self._system_prompt = getattr(settings, "AI_SYSTEM_PROMPT", "") or _DEFAULT_SYSTEM
        self._temperature = settings.DEFAULT_TEMPERATURE
        self._timeout = settings.WORKER_TIMEOUT_SECONDS

        if not self._api_key:
            logger.warning(
                "ANTHROPIC | No API key configured. Set AI_API_KEY in .env."
            )

    # ─────────────────────────────────────────────────────────
    # Public interface
    # ─────────────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        max_tokens: int,
        execution_id: str,
        seed: int,
    ) -> Tuple[str, str, int]:
        """Call the Anthropic Messages API."""
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
        }

        body = {
            "model": self._model_id,
            "max_tokens": max_tokens,
            "system": self._system_prompt,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": self._temperature,
        }

        req = urllib.request.Request(
            _ANTHROPIC_API_URL,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            logger.error(
                "ANTHROPIC_HTTP_ERROR | exec_id=%s status=%d body=%s",
                execution_id, exc.code, body_text[:500],
            )
            raise RuntimeError(
                f"Anthropic API error {exc.code}: {body_text[:300]}"
            ) from exc
        except Exception as exc:
            logger.error("ANTHROPIC_ERROR | exec_id=%s error=%s", execution_id, exc)
            raise RuntimeError(f"Anthropic request failed: {exc}") from exc

        latency_ms = self._measure(t0)
        return self._parse_response(raw, execution_id, latency_ms)

    def health_check(self) -> bool:
        """Check that we can reach Anthropic's API."""
        # Anthropic has no cheap /models list endpoint — we just verify key format
        return bool(self._api_key and self._api_key.startswith("sk-ant-"))

    # ─────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────

    def _parse_response(
        self,
        raw: dict,
        execution_id: str,
        latency_ms: float,
    ) -> Tuple[str, str, int]:
        """
        Parse Anthropic Messages API response.

        Response shape:
        {
          "content": [{"type": "text", "text": "..."}],
          "stop_reason": "end_turn" | "max_tokens" | "stop_sequence",
          "usage": {"input_tokens": 10, "output_tokens": 50}
        }
        """
        content_blocks = raw.get("content", [])
        text = "".join(
            block.get("text", "")
            for block in content_blocks
            if block.get("type") == "text"
        )

        stop_reason_raw = raw.get("stop_reason", "end_turn")
        reason_map = {
            "end_turn":      "stop",
            "max_tokens":    "max_tokens",
            "stop_sequence": "stop",
        }
        stop_reason = reason_map.get(stop_reason_raw, stop_reason_raw)

        usage = raw.get("usage", {})
        token_count = usage.get("output_tokens", len(text.split()))

        logger.info(
            "ANTHROPIC_OK | exec_id=%s tokens=%d latency_ms=%.1f stop=%s",
            execution_id, token_count, latency_ms, stop_reason,
        )
        return text, stop_reason, token_count
