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
        # We don't mutate settings, we just use a fallback endpoint if it's missing
        if not settings.AI_ENDPOINT_URL:
            self._endpoint = _DEFAULT_VLLM_URL
        else:
            self._endpoint = settings.AI_ENDPOINT_URL.rstrip("/")
            
        # Initialize OpenAI compatible adapter with current settings
        # We need to temporarily set the endpoint for the superclass to see it
        # However, OpenAICompatibleAdapter checks settings.AI_ENDPOINT_URL directly,
        # so we will let super().__init__() fail if not set and catch it, or just 
        # override the values post-init.
        
        # Best approach: mock it before super call
        original_endpoint = settings.AI_ENDPOINT_URL
        try:
            # Bypass frozen checks for initialization purposes only if needed,
            # or just override the property after super()
            pass
        except Exception:
            pass
            
        super().__init__()
        
        # Override the endpoint that the superclass grabbed
        if not original_endpoint:
            self._endpoint = _DEFAULT_VLLM_URL
            if settings.IS_DOCKER and ("localhost" in self._endpoint or "127.0.0.1" in self._endpoint):
                logging.getLogger("cgi.adapters.vllm").warning("VLLM | Docker detected. Rewriting localhost -> host.docker.internal")
                self._endpoint = self._endpoint.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
            
        # vLLM doesn't need an API key for local use
        if not self._api_key:
            self._api_key = "no-key-needed"
        logging.getLogger("cgi.adapters.vllm").info(
            "VLLM | endpoint=%s model=%s", self._endpoint, self._model_id
        )
