"""
CGI Protocol — Gemini Native Adapter
======================================
Connects to Google's Gemini API using the native generateContent REST endpoint.

Configuration (via .env or environment):
    AI_BACKEND_TYPE = gemini_native
    AI_API_KEY      = <your Gemini API key>  (or GEMINI_API_KEY for legacy compat)
    MODEL_ID        = gemini-2.5-flash        (default)

Supported models (as of 2026):
    gemini-2.5-flash, gemini-2.5-pro, gemini-1.5-pro-latest,
    gemini-1.5-flash-latest, gemini-2.0-flash-exp
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

logger = logging.getLogger("cgi.adapters.gemini")

_GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiNativeAdapter(BaseAdapter):
    """
    Calls the Gemini generateContent REST endpoint directly.
    No third-party SDK needed — pure stdlib urllib.
    """

    capabilities = AdapterCapabilities(
        supports_streaming=False,
        supports_seed=False,        # Gemini does not support deterministic seeds
        supports_system_prompt=True,
        supports_temperature=True,
        supports_token_count=True,
    )

    def __init__(self) -> None:
        # Prefer explicit AI_API_KEY; fall back to legacy GEMINI_API_KEY env var
        import os
        self._api_key = settings.AI_API_KEY or os.environ.get("GEMINI_API_KEY", "")
        self._model_id = settings.MODEL_ID or "gemini-2.5-flash"
        self._system_prompt = getattr(settings, "AI_SYSTEM_PROMPT", "")
        self._temperature = settings.DEFAULT_TEMPERATURE
        self._timeout = settings.WORKER_TIMEOUT_SECONDS

        if not self._api_key:
            logger.warning(
                "GEMINI | No API key configured. Set AI_API_KEY in .env. "
                "Requests will fail with 401."
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
        """Call Gemini generateContent and return (text, stop_reason, token_count)."""
        url = f"{_GEMINI_API_BASE}/{self._model_id}:generateContent?key={self._api_key}"

        body = self._build_request_body(prompt, max_tokens)
        req_bytes = json.dumps(body).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=req_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            logger.error(
                "GEMINI_HTTP_ERROR | exec_id=%s status=%d body=%s",
                execution_id, exc.code, body_text[:500],
            )
            raise RuntimeError(
                f"Gemini API error {exc.code}: {body_text[:200]}"
            ) from exc
        except Exception as exc:
            logger.error("GEMINI_ERROR | exec_id=%s error=%s", execution_id, exc)
            raise RuntimeError(f"Gemini request failed: {exc}") from exc

        latency_ms = self._measure(t0)
        return self._parse_response(raw, execution_id, latency_ms)

    def health_check(self) -> bool:
        """Verify the API key is valid by listing available models."""
        if not self._api_key:
            return False
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={self._api_key}&pageSize=1"
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return r.status == 200
        except Exception:
            return False

    # ─────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────

    def _build_request_body(self, prompt: str, max_tokens: int) -> dict:
        """Build the Gemini generateContent request body."""
        body: dict = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": self._temperature,
            },
        }

        # Inject system instruction if configured
        if self._system_prompt:
            body["systemInstruction"] = {
                "parts": [{"text": self._system_prompt}]
            }

        return body

    def _parse_response(
        self,
        raw: dict,
        execution_id: str,
        latency_ms: float,
    ) -> Tuple[str, str, int]:
        """
        Parse Gemini's native generateContent response format.

        Gemini response shape:
        {
          "candidates": [
            {
              "content": {"parts": [{"text": "..."}], "role": "model"},
              "finishReason": "STOP",
              ...
            }
          ],
          "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 50,
            "totalTokenCount": 60
          }
        }
        """
        candidates = raw.get("candidates", [])
        if not candidates:
            # Gemini sometimes returns an empty candidates list when safety filters fire
            prompt_feedback = raw.get("promptFeedback", {})
            block_reason = prompt_feedback.get("blockReason", "UNKNOWN")
            logger.warning(
                "GEMINI_BLOCKED | exec_id=%s reason=%s", execution_id, block_reason
            )
            return (
                f"[CONTENT_BLOCKED: {block_reason}]",
                "content_filter",
                0,
            )

        candidate = candidates[0]
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        text = "".join(p.get("text", "") for p in parts)

        finish_reason = candidate.get("finishReason", "STOP").lower()
        # Normalise Gemini's finish reasons to the CGI standard set
        reason_map = {
            "stop": "stop",
            "max_tokens": "max_tokens",
            "safety": "content_filter",
            "recitation": "content_filter",
            "other": "unknown",
        }
        stop_reason = reason_map.get(finish_reason, finish_reason)

        usage = raw.get("usageMetadata", {})
        token_count = usage.get("candidatesTokenCount", len(text.split()))

        logger.info(
            "GEMINI_OK | exec_id=%s tokens=%d latency_ms=%.1f stop=%s",
            execution_id, token_count, latency_ms, stop_reason,
        )
        return text, stop_reason, token_count
