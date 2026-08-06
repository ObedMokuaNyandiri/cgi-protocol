"""
CGI Protocol — Together AI Adapter
=====================================
Together AI offers a large catalogue of open-source models via an
OpenAI-compatible API with competitive pricing.

Configuration:
    AI_BACKEND_TYPE = together_ai
    AI_API_KEY      = <Together API key>
    MODEL_ID        = meta-llama/Llama-3.3-70B-Instruct-Turbo

Popular models:
    meta-llama/Llama-3.3-70B-Instruct-Turbo
    meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo
    mistralai/Mixtral-8x7B-Instruct-v0.1
    Qwen/Qwen2.5-72B-Instruct-Turbo
    deepseek-ai/DeepSeek-V3

Docs: https://docs.together.ai/reference/chat-completions
"""

from __future__ import annotations

from adapters.openai_compatible import OpenAICompatibleAdapter

_TOGETHER_BASE_URL = "https://api.together.xyz/v1"


class TogetherAIAdapter(OpenAICompatibleAdapter):
    """Together AI adapter — inherits OpenAI-compatible implementation."""

    def __init__(self) -> None:
        from config import settings
        import logging
        if not settings.AI_ENDPOINT_URL or "together" not in settings.AI_ENDPOINT_URL:
            settings.__dict__["AI_ENDPOINT_URL"] = _TOGETHER_BASE_URL
        super().__init__()
        self._endpoint = _TOGETHER_BASE_URL
        logging.getLogger("cgi.adapters.together").info(
            "TOGETHER_AI | model=%s", self._model_id
        )
