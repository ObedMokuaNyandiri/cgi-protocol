"""
CGI Protocol — Mistral API Adapter
=====================================
Connects to Mistral AI's la Plateforme API.

Configuration:
    AI_BACKEND_TYPE = mistral
    AI_API_KEY      = <Mistral API key>
    MODEL_ID        = mistral-large-latest

Models: mistral-large-latest, mistral-medium-latest, mistral-small-latest,
        codestral-latest, open-mistral-7b, open-mixtral-8x7b

Docs: https://docs.mistral.ai/api/
"""

from __future__ import annotations

from adapters.openai_compatible import OpenAICompatibleAdapter

_MISTRAL_BASE_URL = "https://api.mistral.ai/v1"


class MistralAdapter(OpenAICompatibleAdapter):
    """
    Mistral AI adapter. Mistral is OpenAI-compatible so we reuse
    OpenAICompatibleAdapter with Mistral's base URL.
    """

    def __init__(self) -> None:
        from config import settings
        import logging
        # Ensure endpoint points to Mistral
        if not settings.AI_ENDPOINT_URL or "mistral.ai" not in settings.AI_ENDPOINT_URL:
            settings.__dict__["AI_ENDPOINT_URL"] = _MISTRAL_BASE_URL
        super().__init__()
        self._endpoint = _MISTRAL_BASE_URL
        logging.getLogger("cgi.adapters.mistral").info(
            "MISTRAL | model=%s", self._model_id
        )
