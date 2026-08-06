"""
CGI Protocol — HuggingFace Inference API Adapter
==================================================
Connects to HuggingFace's hosted Inference API (serverless or dedicated endpoints).
Lets you run any model hosted on the HuggingFace Hub without local hardware.

Configuration:
    AI_BACKEND_TYPE = huggingface_api
    AI_API_KEY      = hf_...             (HuggingFace User Access Token)
    MODEL_ID        = mistralai/Mistral-7B-Instruct-v0.2
    AI_ENDPOINT_URL = (optional, for private/dedicated endpoints)

For dedicated endpoints, set:
    AI_ENDPOINT_URL = https://your-endpoint.endpoints.huggingface.cloud

Docs: https://huggingface.co/docs/api-inference/quicktour
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

logger = logging.getLogger("cgi.adapters.hf_api")

_HF_API_BASE = "https://api-inference.huggingface.co/models"


class HuggingFaceInferenceAPIAdapter(BaseAdapter):
    """
    Calls HuggingFace's Inference API for hosted model inference.
    Supports both the free Serverless Inference API and dedicated endpoints.
    """

    capabilities = AdapterCapabilities(
        supports_streaming=False,
        supports_seed=True,
        supports_system_prompt=True,
        supports_temperature=True,
        supports_token_count=False,  # HF Inference API doesn't always return token counts
    )

    def __init__(self) -> None:
        self._api_key = settings.AI_API_KEY
        self._model_id = settings.MODEL_ID
        self._system_prompt = getattr(settings, "AI_SYSTEM_PROMPT", "") or (
            "You are a controlled inference engine. Answer concisely and precisely."
        )
        self._temperature = settings.DEFAULT_TEMPERATURE
        self._timeout = settings.WORKER_TIMEOUT_SECONDS

        # Custom endpoint for dedicated/private endpoints
        custom_endpoint = settings.AI_ENDPOINT_URL
        if custom_endpoint:
            self._url = custom_endpoint.rstrip("/")
        else:
            self._url = f"{_HF_API_BASE}/{self._model_id}"

        if not self._api_key:
            logger.warning(
                "HF_API | No API key. Set AI_API_KEY=hf_... for private/rate-limited models."
            )

        logger.info("HF_API | url=%s model=%s", self._url, self._model_id)

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
        """Call HuggingFace Inference API using the chat completions format."""
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        # Use chat_completions format for instruct models
        messages = [
            {"role": "system", "content": self._system_prompt},
            {"role": "user", "content": prompt},
        ]

        body = {
            "model": self._model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": self._temperature,
            "seed": seed,
            "stream": False,
        }

        req = urllib.request.Request(
            self._url if "/chat/completions" in self._url
            else f"{self._url}/v1/chat/completions",
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
            # 503 = model loading; give a helpful message
            if exc.code == 503:
                raise RuntimeError(
                    f"HuggingFace model '{self._model_id}' is loading. "
                    "Try again in 20-60 seconds."
                ) from exc
            logger.error(
                "HF_API_HTTP_ERROR | exec_id=%s status=%d body=%s",
                execution_id, exc.code, body_text[:500],
            )
            raise RuntimeError(
                f"HuggingFace API error {exc.code}: {body_text[:300]}"
            ) from exc
        except Exception as exc:
            logger.error("HF_API_ERROR | exec_id=%s error=%s", execution_id, exc)
            raise RuntimeError(f"HuggingFace API request failed: {exc}") from exc

        latency_ms = self._measure(t0)
        return self._parse_response(raw, execution_id, latency_ms)

    def health_check(self) -> bool:
        """Check the model endpoint is available."""
        return bool(self._model_id)

    # ─────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────

    def _parse_response(
        self,
        raw: dict,
        execution_id: str,
        latency_ms: float,
    ) -> Tuple[str, str, int]:
        # OpenAI-compatible chat completions format
        choices = raw.get("choices", [])
        if choices:
            choice = choices[0]
            text = choice.get("message", {}).get("content", "") or ""
            stop_reason = choice.get("finish_reason", "stop") or "stop"
            usage = raw.get("usage", {})
            token_count = usage.get("completion_tokens", len(text.split()))
        else:
            # Fallback: text generation format
            if isinstance(raw, list) and raw:
                text = raw[0].get("generated_text", "")
            else:
                text = raw.get("generated_text", "")
            stop_reason = "stop"
            token_count = len(text.split())

        logger.info(
            "HF_API_OK | exec_id=%s tokens=%d latency_ms=%.1f stop=%s",
            execution_id, token_count, latency_ms, stop_reason,
        )
        return text, stop_reason, token_count
