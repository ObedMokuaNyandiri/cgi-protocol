"""
CGI Protocol — Cohere Command Adapter
========================================
Connects to Cohere's Chat API for Command R / Command R+ models.

Configuration:
    AI_BACKEND_TYPE  = cohere
    AI_API_KEY       = <Cohere API key>
    MODEL_ID         = command-r-plus-08-2024

Models: command-r-plus-08-2024, command-r-08-2024, command-light, command

Docs: https://docs.cohere.com/reference/chat
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

logger = logging.getLogger("cgi.adapters.cohere")

_COHERE_CHAT_URL = "https://api.cohere.ai/v1/chat"
_DEFAULT_MODEL = "command-r-plus-08-2024"
_DEFAULT_PREAMBLE = (
    "You are a controlled inference engine operating under cryptographic governance. "
    "Answer concisely and with technical precision."
)


class CohereCommandAdapter(BaseAdapter):
    """
    Calls Cohere's Chat API for Command R / Command R+ models.
    Uses Cohere's native format (not OpenAI-compatible).
    """

    capabilities = AdapterCapabilities(
        supports_streaming=False,
        supports_seed=True,
        supports_system_prompt=True,   # Via 'preamble' field
        supports_temperature=True,
        supports_token_count=True,
    )

    def __init__(self) -> None:
        self._api_key = settings.AI_API_KEY
        self._model_id = settings.MODEL_ID or _DEFAULT_MODEL
        self._preamble = getattr(settings, "AI_SYSTEM_PROMPT", "") or _DEFAULT_PREAMBLE
        self._temperature = settings.DEFAULT_TEMPERATURE
        self._timeout = settings.WORKER_TIMEOUT_SECONDS

        if not self._api_key:
            logger.warning("COHERE | No API key set. Requests will fail.")

    # ─────────────────────────────────────────────────────────
    # Public interface
    # ─────────────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        model_id: str,
        max_tokens: int,
        execution_id: str,
        seed: int,
    ) -> Tuple[str, str, int]:
        """Call the Cohere Chat API."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }

        active_model = model_id if model_id else self._model_id
        body = {
            "model": active_model,
            "message": prompt,
            "preamble": self._preamble,
            "max_tokens": max_tokens,
            "temperature": self._temperature,
            "seed": seed,
        }

        req = urllib.request.Request(
            _COHERE_CHAT_URL,
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
                "COHERE_HTTP_ERROR | exec_id=%s status=%d body=%s",
                execution_id, exc.code, body_text[:500],
            )
            raise RuntimeError(
                f"Cohere API error {exc.code}: {body_text[:300]}"
            ) from exc
        except Exception as exc:
            logger.error("COHERE_ERROR | exec_id=%s error=%s", execution_id, exc)
            raise RuntimeError(f"Cohere request failed: {exc}") from exc

        latency_ms = self._measure(t0)
        return self._parse_response(raw, execution_id, latency_ms)

    def health_check(self) -> bool:
        return bool(self._api_key)

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
        Parse Cohere Chat API response.

        Response shape:
        {
          "text": "...",
          "finish_reason": "COMPLETE" | "MAX_TOKENS",
          "meta": {"tokens": {"input_tokens": 10, "output_tokens": 50}}
        }
        """
        text = raw.get("text", "")
        finish_reason = raw.get("finish_reason", "COMPLETE")
        reason_map = {"COMPLETE": "stop", "MAX_TOKENS": "max_tokens", "ERROR": "error"}
        stop_reason = reason_map.get(finish_reason, finish_reason.lower())

        meta = raw.get("meta", {})
        billed = meta.get("billed_units", {})
        token_count = billed.get("output_tokens", len(text.split()))

        logger.info(
            "COHERE_OK | exec_id=%s tokens=%d latency_ms=%.1f stop=%s",
            execution_id, token_count, latency_ms, stop_reason,
        )
        return text, stop_reason, token_count
