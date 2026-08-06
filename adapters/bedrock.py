"""
CGI Protocol — AWS Bedrock Adapter
=====================================
Connects to AWS Bedrock for managed inference of Claude, Titan, Llama, and
other foundation models hosted on AWS infrastructure.

Configuration:
    AI_BACKEND_TYPE        = bedrock
    AWS_ACCESS_KEY_ID      = <your AWS key>
    AWS_SECRET_ACCESS_KEY  = <your AWS secret>
    AWS_DEFAULT_REGION     = us-east-1
    MODEL_ID               = anthropic.claude-3-5-sonnet-20241022-v2:0

Common Bedrock model IDs:
    anthropic.claude-3-5-sonnet-20241022-v2:0
    anthropic.claude-3-haiku-20240307-v1:0
    meta.llama3-3-70b-instruct-v1:0
    amazon.titan-text-express-v1
    mistral.mistral-large-2402-v1:0

Requires boto3: pip install boto3
Docs: https://docs.aws.amazon.com/bedrock/latest/userguide/inference.html
"""

from __future__ import annotations

import json
import logging
import time
from typing import Tuple

from config import settings
from adapters.base import BaseAdapter, AdapterCapabilities

logger = logging.getLogger("cgi.adapters.bedrock")

_DEFAULT_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"


class BedrockAdapter(BaseAdapter):
    """
    AWS Bedrock adapter using the Converse API (unified multi-model interface).
    Requires boto3 to be installed: pip install boto3
    """

    capabilities = AdapterCapabilities(
        supports_streaming=False,
        supports_seed=False,
        supports_system_prompt=True,
        supports_temperature=True,
        supports_token_count=True,
    )

    def __init__(self) -> None:
        try:
            import boto3
            self._boto3 = boto3
        except ImportError as exc:
            raise ImportError(
                "AWS Bedrock adapter requires boto3. Install with: pip install boto3"
            ) from exc

        import os
        self._region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self._model_id = settings.MODEL_ID or _DEFAULT_MODEL
        self._system_prompt = getattr(settings, "AI_SYSTEM_PROMPT", "") or (
            "You are a controlled inference engine. Answer concisely and precisely."
        )
        self._temperature = settings.DEFAULT_TEMPERATURE
        self._max_tokens_default = settings.DEFAULT_MAX_TOKENS

        self._client = boto3.client(
            "bedrock-runtime",
            region_name=self._region,
        )
        logger.info("BEDROCK | model=%s region=%s", self._model_id, self._region)

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
        """
        Use Bedrock Converse API — works across all Bedrock models uniformly.
        """
        converse_params = {
            "modelId": self._model_id,
            "messages": [
                {"role": "user", "content": [{"text": prompt}]}
            ],
            "inferenceConfig": {
                "maxTokens": max_tokens,
                "temperature": self._temperature,
            },
        }

        if self._system_prompt:
            converse_params["system"] = [{"text": self._system_prompt}]

        t0 = time.monotonic()
        try:
            response = self._client.converse(**converse_params)
        except Exception as exc:
            logger.error("BEDROCK_ERROR | exec_id=%s error=%s", execution_id, exc)
            raise RuntimeError(f"AWS Bedrock request failed: {exc}") from exc

        latency_ms = self._measure(t0)
        return self._parse_response(response, execution_id, latency_ms)

    def health_check(self) -> bool:
        """List Bedrock foundation models to verify connectivity."""
        try:
            client = self._boto3.client("bedrock", region_name=self._region)
            client.list_foundation_models(byOutputModality="TEXT")
            return True
        except Exception:
            return False

    # ─────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────

    def _parse_response(
        self,
        response: dict,
        execution_id: str,
        latency_ms: float,
    ) -> Tuple[str, str, int]:
        """
        Parse Bedrock Converse API response.

        Response shape:
        {
          "output": {"message": {"content": [{"text": "..."}]}},
          "stopReason": "end_turn",
          "usage": {"inputTokens": 10, "outputTokens": 50}
        }
        """
        output = response.get("output", {})
        message = output.get("message", {})
        content_blocks = message.get("content", [])
        text = "".join(b.get("text", "") for b in content_blocks if "text" in b)

        stop_reason_raw = response.get("stopReason", "end_turn")
        reason_map = {"end_turn": "stop", "max_tokens": "max_tokens"}
        stop_reason = reason_map.get(stop_reason_raw, stop_reason_raw)

        usage = response.get("usage", {})
        token_count = usage.get("outputTokens", len(text.split()))

        logger.info(
            "BEDROCK_OK | exec_id=%s tokens=%d latency_ms=%.1f stop=%s",
            execution_id, token_count, latency_ms, stop_reason,
        )
        return text, stop_reason, token_count
