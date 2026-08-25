"""
CGI Protocol — OpenAI-Compatible Adapter
==========================================
Works with any OpenAI-compatible API including:
  - OpenAI (api.openai.com)
  - Groq (api.groq.com/openai)
  - Together AI (api.together.xyz)
  - Mistral (api.mistral.ai)
  - LM Studio (local, http://localhost:1234)
  - Any other OpenAI-spec compatible endpoint

Configuration (via .env or environment):
    AI_BACKEND_TYPE  = openai_compatible
    AI_ENDPOINT_URL  = https://api.openai.com/v1   (or your custom endpoint)
    AI_API_KEY       = sk-...
    MODEL_ID         = gpt-4o-mini                  (or any model name)
    AI_SYSTEM_PROMPT = (optional system instruction)
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

logger = logging.getLogger("cgi.adapters.openai")

_DEFAULT_SYSTEM_PROMPT = (
    "You are a controlled inference engine. "
    "Answer concisely and with technical precision."
)


class OpenAICompatibleAdapter(BaseAdapter):
    """
    Calls any OpenAI /chat/completions compatible REST endpoint.
    Uses only stdlib urllib — no third-party HTTP client required.
    """

    capabilities = AdapterCapabilities(
        supports_streaming=False,
        supports_seed=True,
        supports_system_prompt=True,
        supports_temperature=True,
        supports_token_count=True,
    )

    def __init__(self) -> None:
        self._endpoint = (settings.AI_ENDPOINT_URL or "").rstrip("/")
        if settings.IS_DOCKER and ("localhost" in self._endpoint or "127.0.0.1" in self._endpoint):
            logger.warning("OPENAI | Docker detected. Rewriting localhost -> host.docker.internal")
            self._endpoint = self._endpoint.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")

        self._api_key = settings.AI_API_KEY
        self._model_id = settings.MODEL_ID
        self._system_prompt = (
            getattr(settings, "AI_SYSTEM_PROMPT", "") or _DEFAULT_SYSTEM_PROMPT
        )
        self._temperature = settings.DEFAULT_TEMPERATURE
        self._timeout = settings.WORKER_TIMEOUT_SECONDS

        if not self._endpoint:
            raise ValueError(
                "OpenAI-compatible adapter requires AI_ENDPOINT_URL. "
                "Example: AI_ENDPOINT_URL=https://api.openai.com/v1"
            )

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
        """Call the /chat/completions endpoint and return (text, stop_reason, token_count)."""
        url = f"{self._endpoint}/chat/completions"

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        active_model = model_id if model_id else self._model_id
        
        payload = {
            "model": active_model,
            "messages": [
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": self._temperature,
            "seed": seed,
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
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
                "OPENAI_HTTP_ERROR | exec_id=%s status=%d url=%s body=%s",
                execution_id, exc.code, url, body_text[:500],
            )
            raise RuntimeError(
                f"OpenAI-compatible API error {exc.code}: {body_text[:300]}"
            ) from exc
        except urllib.error.URLError as exc:
            logger.error(
                "OPENAI_URL_ERROR | exec_id=%s url=%s reason=%s",
                execution_id, url, exc.reason,
            )
            raise RuntimeError(
                f"Cannot reach {url}: {exc.reason}"
            ) from exc
        except Exception as exc:
            logger.error("OPENAI_ERROR | exec_id=%s error=%s", execution_id, exc)
            raise RuntimeError(f"OpenAI-compatible request failed: {exc}") from exc

        latency_ms = self._measure(t0)
        return self._parse_response(raw, execution_id, latency_ms)

    def health_check(self) -> bool:
        """Ping the /models endpoint to verify connectivity."""
        url = f"{self._endpoint}/models"
        headers: dict = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status == 200
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Fetch available models from the /models endpoint."""
        url = f"{self._endpoint}/models"
        headers: dict = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode("utf-8"))
            return [m.get("id", "") for m in data.get("data", [])]
        except Exception:
            return []

    # ─────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────

    def _parse_response(
        self,
        raw: dict,
        execution_id: str,
        latency_ms: float,
    ) -> Tuple[str, str, int]:
        choices = raw.get("choices", [])
        if not choices:
            logger.warning("OPENAI_EMPTY_CHOICES | exec_id=%s raw=%s", execution_id, raw)
            return "", "unknown", 0

        choice = choices[0]
        text = choice.get("message", {}).get("content", "") or ""
        stop_reason = choice.get("finish_reason", "unknown") or "unknown"
        usage = raw.get("usage", {})
        token_count = usage.get("completion_tokens", len(text.split()))

        logger.info(
            "OPENAI_OK | exec_id=%s tokens=%d latency_ms=%.1f stop=%s",
            execution_id, token_count, latency_ms, stop_reason,
        )
        return text, stop_reason, token_count
