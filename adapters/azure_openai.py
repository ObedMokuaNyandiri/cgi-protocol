"""
CGI Protocol — Azure OpenAI Adapter
=======================================
Connects to Azure OpenAI Service deployments.
Azure uses a different URL format and authentication header from OpenAI.

Configuration (via .env or environment):
    AI_BACKEND_TYPE          = azure_openai
    AZURE_OPENAI_RESOURCE    = my-resource           (your Azure resource name)
    AZURE_OPENAI_DEPLOYMENT  = gpt-4o-deployment     (your deployment name)
    AZURE_API_VERSION        = 2024-02-01            (API version)
    AI_API_KEY               = <Azure OpenAI key>    (from Azure portal)
    AI_SYSTEM_PROMPT         = (optional)

The endpoint is auto-constructed as:
  https://{RESOURCE}.openai.azure.com/openai/deployments/{DEPLOYMENT}/chat/completions?api-version={VERSION}

Docs: https://learn.microsoft.com/en-us/azure/ai-services/openai/reference
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

logger = logging.getLogger("cgi.adapters.azure_openai")

_DEFAULT_API_VERSION = "2024-02-01"
_DEFAULT_SYSTEM = (
    "You are a controlled inference engine. Answer concisely and precisely."
)


class AzureOpenAIAdapter(BaseAdapter):
    """
    Calls Azure OpenAI Service's chat completions endpoint.
    Authentication via api-key header (not Bearer).
    """

    capabilities = AdapterCapabilities(
        supports_streaming=False,
        supports_seed=True,
        supports_system_prompt=True,
        supports_temperature=True,
        supports_token_count=True,
    )

    def __init__(self) -> None:
        import os
        self._resource = os.environ.get("AZURE_OPENAI_RESOURCE", "")
        self._deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", settings.MODEL_ID)
        self._api_version = os.environ.get("AZURE_API_VERSION", _DEFAULT_API_VERSION)
        self._api_key = settings.AI_API_KEY
        self._system_prompt = getattr(settings, "AI_SYSTEM_PROMPT", "") or _DEFAULT_SYSTEM
        self._temperature = settings.DEFAULT_TEMPERATURE
        self._timeout = settings.WORKER_TIMEOUT_SECONDS

        if not self._resource:
            raise ValueError(
                "Azure OpenAI requires AZURE_OPENAI_RESOURCE env var. "
                "Example: AZURE_OPENAI_RESOURCE=my-company-openai"
            )
        if not self._api_key:
            raise ValueError(
                "Azure OpenAI requires AI_API_KEY. "
                "Find it in Azure Portal → OpenAI resource → Keys and Endpoint."
            )

        # URL is constructed dynamically in generate()
        logger.info("AZURE_OPENAI | resource=%s", self._resource)

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
        """Call Azure OpenAI /chat/completions."""
        headers = {
            "Content-Type": "application/json",
            "api-key": self._api_key,   # Azure uses api-key, not Authorization: Bearer
        }
        
        active_deployment = model_id if model_id else self._deployment
        url = (
            f"https://{self._resource}.openai.azure.com"
            f"/openai/deployments/{active_deployment}"
            f"/chat/completions?api-version={self._api_version}"
        )

        payload = {
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
                "AZURE_HTTP_ERROR | exec_id=%s status=%d body=%s",
                execution_id, exc.code, body_text[:500],
            )
            raise RuntimeError(
                f"Azure OpenAI error {exc.code}: {body_text[:300]}"
            ) from exc
        except Exception as exc:
            logger.error("AZURE_ERROR | exec_id=%s error=%s", execution_id, exc)
            raise RuntimeError(f"Azure OpenAI request failed: {exc}") from exc

        latency_ms = self._measure(t0)
        return self._parse_response(raw, execution_id, latency_ms)

    def health_check(self) -> bool:
        """Verify the Azure deployment is reachable."""
        return bool(self._api_key and self._resource and self._deployment)

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
            return "", "unknown", 0

        choice = choices[0]
        text = choice.get("message", {}).get("content", "") or ""
        stop_reason = choice.get("finish_reason", "stop") or "stop"
        usage = raw.get("usage", {})
        token_count = usage.get("completion_tokens", len(text.split()))

        logger.info(
            "AZURE_OK | exec_id=%s tokens=%d latency_ms=%.1f stop=%s",
            execution_id, token_count, latency_ms, stop_reason,
        )
        return text, stop_reason, token_count
