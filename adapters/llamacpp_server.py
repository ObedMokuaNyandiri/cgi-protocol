"""
CGI Protocol — llama.cpp HTTP Server Adapter
=============================================
llama.cpp's built-in HTTP server exposes an OpenAI-compatible API.
Ideal for running quantized GGUF models on CPU or Apple Silicon.

Configuration:
    AI_BACKEND_TYPE = llamacpp_server
    AI_ENDPOINT_URL = http://localhost:8080   (or your llama.cpp server URL)
    MODEL_ID        = (set when starting the server, ignored here)

Start llama.cpp server:
    ./llama-server -m models/llama-3.2-3b.Q4_K_M.gguf --port 8080

Or with full OpenAI compat mode:
    ./llama-server -m model.gguf --port 8080 -c 4096

Docs: https://github.com/ggerganov/llama.cpp/blob/master/tools/server/README.md
"""

from __future__ import annotations

from adapters.openai_compatible import OpenAICompatibleAdapter

_DEFAULT_LLAMACPP_URL = "http://localhost:8080/v1"


class LlamaCppServerAdapter(OpenAICompatibleAdapter):
    """
    llama.cpp server adapter — uses its OpenAI-compatible /v1/chat/completions endpoint.
    """

    def __init__(self) -> None:
        from config import settings
        import logging
        
        original_endpoint = settings.AI_ENDPOINT_URL
        super().__init__()
        
        if not original_endpoint:
            self._endpoint = _DEFAULT_LLAMACPP_URL
            if settings.IS_DOCKER and ("localhost" in self._endpoint or "127.0.0.1" in self._endpoint):
                logging.getLogger("cgi.adapters.llamacpp").warning("LLAMACPP | Docker detected. Rewriting localhost -> host.docker.internal")
                self._endpoint = self._endpoint.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
            
        if not self._api_key:
            self._api_key = "no-key-needed"
        logging.getLogger("cgi.adapters.llamacpp").info(
            "LLAMACPP | endpoint=%s", self._endpoint
        )
