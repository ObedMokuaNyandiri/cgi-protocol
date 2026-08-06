"""
CGI Protocol — Groq API Adapter
=================================
Groq offers ultra-fast inference for open-source models (Llama, Mixtral, Gemma)
via an OpenAI-compatible API with sub-second latency.

Configuration:
    AI_BACKEND_TYPE = groq
    AI_API_KEY      = gsk_...    (Groq API key from console.groq.com)
    MODEL_ID        = llama-3.3-70b-versatile

Popular models: llama-3.3-70b-versatile, llama-3.1-8b-instant,
                mixtral-8x7b-32768, gemma2-9b-it, llama-guard-3-8b
"""

from __future__ import annotations

from config import settings
from adapters.openai_compatible import OpenAICompatibleAdapter

_GROQ_BASE_URL = "https://api.groq.com/openai/v1"


class GroqAdapter(OpenAICompatibleAdapter):
    """
    Groq-specific adapter. Groq is fully OpenAI-compatible so we reuse
    OpenAICompatibleAdapter with the Groq base URL pre-configured.
    """

    def __init__(self) -> None:
        # Temporarily override endpoint to Groq's URL
        original_url = settings.AI_ENDPOINT_URL
        if not original_url or "groq.com" not in original_url:
            settings.__dict__["AI_ENDPOINT_URL"] = _GROQ_BASE_URL  # noqa: SLF001
        super().__init__()
        # Restore (settings is a singleton; this is safe for single-process use)
        if not original_url or "groq.com" not in original_url:
            settings.__dict__["AI_ENDPOINT_URL"] = original_url  # noqa: SLF001
        self._endpoint = _GROQ_BASE_URL
        import logging
        self._logger = logging.getLogger("cgi.adapters.groq")
        self._logger.info("GROQ | model=%s", self._model_id)
