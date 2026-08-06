"""
CGI Protocol — vLLM Local Server Adapter
==========================================
vLLM is the fastest open-source inference server for LLMs.
It exposes an OpenAI-compatible API so we can reuse the OpenAI adapter.

Configuration:
    AI_BACKEND_TYPE = vllm_local
    AI_ENDPOINT_URL = http://localhost:8000   (or your vLLM server URL)
    MODEL_ID        = meta-llama/Llama-3.2-3B-Instruct

Start vLLM server:
    pip install vllm
    vllm serve meta-llama/Llama-3.2-3B-Instruct --port 8000

Docs: https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html
"""

from __future__ import annotations

from adapters.openai_compatible import OpenAICompatibleAdapter

_DEFAULT_VLLM_URL = "http://localhost:8000/v1"


class VLLMLocalAdapter(OpenAICompatibleAdapter):
    """
    vLLM server adapter — uses the OpenAI-compatible endpoint exposed by vLLM.
    vLLM is fully OpenAI spec compliant, so we just inherit OpenAICompatibleAdapter.
    """

    def __init__(self) -> None:
        from config import settings
        import logging
        if not settings.AI_ENDPOINT_URL:
            settings.__dict__["AI_ENDPOINT_URL"] = _DEFAULT_VLLM_URL
        super().__init__()
        # vLLM doesn't need an API key for local use
        if not self._api_key:
            self._api_key = "no-key-needed"
        logging.getLogger("cgi.adapters.vllm").info(
            "VLLM | endpoint=%s model=%s", self._endpoint, self._model_id
        )
