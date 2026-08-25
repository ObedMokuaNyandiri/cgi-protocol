"""
CGI Protocol — Ollama Local Adapter
=====================================
Connects to a locally-running Ollama server.
Ollama lets you run Llama, Mistral, Phi, Gemma, Qwen, DeepSeek, and many
other open-source models on your own machine with zero cloud dependency.

Configuration (via .env or environment):
    AI_BACKEND_TYPE  = ollama_local
    AI_ENDPOINT_URL  = http://localhost:11434   (default)
    MODEL_ID         = llama3.2                 (or any pulled model)

Install Ollama: https://ollama.ai
Pull a model:   ollama pull llama3.2
Docs:           https://github.com/ollama/ollama/blob/main/docs/api.md
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

logger = logging.getLogger("cgi.adapters.ollama")

_DEFAULT_OLLAMA_URL = "http://localhost:11434"


class OllamaLocalAdapter(BaseAdapter):
    """
    Calls Ollama's REST API running on localhost (or any configured host).
    Zero external dependencies — uses stdlib urllib.
    """

    capabilities = AdapterCapabilities(
        supports_streaming=False,
        supports_seed=True,
        supports_system_prompt=True,
        supports_temperature=True,
        supports_token_count=True,
        requires_local_model=True,
    )

    def __init__(self) -> None:
        self._base_url = (settings.AI_ENDPOINT_URL or _DEFAULT_OLLAMA_URL).rstrip("/")
        if settings.IS_DOCKER and ("localhost" in self._base_url or "127.0.0.1" in self._base_url):
            logger.warning("OLLAMA | Docker detected. Rewriting localhost -> host.docker.internal")
            self._base_url = self._base_url.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")

        self._model_id = settings.MODEL_ID or "llama3.2"
        self._system_prompt = getattr(settings, "AI_SYSTEM_PROMPT", "") or (
            "You are a controlled inference engine. Answer concisely and precisely."
        )
        self._temperature = settings.DEFAULT_TEMPERATURE
        self._timeout = settings.WORKER_TIMEOUT_SECONDS

        logger.info(
            "OLLAMA | endpoint=%s model=%s", self._base_url, self._model_id
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
        """Call Ollama /api/generate (non-streaming)."""
        url = f"{self._base_url}/api/generate"

        active_model = model_id if model_id else self._model_id
        body = {
            "model": active_model,
            "prompt": prompt,
            "system": self._system_prompt,
            "stream": False,
            "options": {
                "temperature": self._temperature,
                "seed": seed,
                "num_predict": max_tokens,
            },
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            logger.error(
                "OLLAMA_UNREACHABLE | exec_id=%s url=%s reason=%s",
                execution_id, self._base_url, exc.reason,
            )
            raise RuntimeError(
                f"Cannot reach Ollama at {self._base_url}. "
                "Is Ollama running? Try: ollama serve"
            ) from exc
        except Exception as exc:
            logger.error("OLLAMA_ERROR | exec_id=%s error=%s", execution_id, exc)
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

        latency_ms = self._measure(t0)
        return self._parse_response(raw, execution_id, latency_ms)

    def health_check(self) -> bool:
        """Check Ollama is running and the model is available."""
        try:
            url = f"{self._base_url}/api/tags"
            with urllib.request.urlopen(url, timeout=5) as r:
                data = json.loads(r.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            # Check if our model is pulled (name might include :tag)
            model_base = self._model_id.split(":")[0]
            return any(model_base in m for m in models)
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return locally available Ollama models."""
        try:
            url = f"{self._base_url}/api/tags"
            with urllib.request.urlopen(url, timeout=5) as r:
                data = json.loads(r.read().decode("utf-8"))
            return [m.get("name", "") for m in data.get("models", [])]
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
        """
        Parse Ollama /api/generate response.

        Response shape:
        {
          "response": "...",
          "done": true,
          "done_reason": "stop",
          "eval_count": 50,
          ...
        }
        """
        text = raw.get("response", "")
        done_reason = raw.get("done_reason", "stop") or "stop"
        token_count = raw.get("eval_count", len(text.split()))

        logger.info(
            "OLLAMA_OK | exec_id=%s tokens=%d latency_ms=%.1f stop=%s",
            execution_id, token_count, latency_ms, done_reason,
        )
        return text, done_reason, token_count
