"""
CGI Protocol — Universal Adapter Registry
==========================================
Maps AI_BACKEND_TYPE to the corresponding adapter class.
Adding a new backend = add one line to ADAPTER_REGISTRY.

Supported backends (set AI_BACKEND_TYPE to one of these):

  CLOUD APIs (API key required):
    gemini_native        — Google Gemini (gemini-2.5-flash, gemini-2.5-pro, etc.)
    openai_compatible    — OpenAI, or any OpenAI-spec API (LM Studio, etc.)
    anthropic            — Anthropic Claude (claude-sonnet-4-5, claude-opus-4-5, etc.)
    azure_openai         — Azure OpenAI Service (gpt-4o, gpt-4-turbo, etc.)
    groq                 — Groq (llama-3.3-70b-versatile, mixtral-8x7b, etc.)
    mistral              — Mistral AI (mistral-large-latest, mistral-small-latest, etc.)
    together_ai          — Together AI (Llama, Mixtral, Qwen, DeepSeek, etc.)
    huggingface_api      — HuggingFace Inference API (any HF Hub model)

    cohere               — Cohere Command R / Command R+

  LOCAL / SELF-HOSTED (no API key):
    ollama_local         — Ollama (run any model locally via ollama serve)
    vllm_local           — vLLM server (OpenAI-compatible, high-throughput)
    llamacpp_server      — llama.cpp HTTP server (quantized GGUF models)
    huggingface_local    — HuggingFace local model (subprocess, legacy)

Usage:
    # In .env:
    AI_BACKEND_TYPE=gemini_native
    AI_API_KEY=your_key_here
    MODEL_ID=gemini-2.5-flash

    # In code (singleton created at startup):
    from adapters import get_inference_adapter
    adapter = get_inference_adapter()
    text, stop, tokens = adapter.generate(prompt, max_tokens, exec_id, seed)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from config import settings
from adapters.base import BaseAdapter

if TYPE_CHECKING:
    pass

logger = logging.getLogger("cgi.adapters")


# ─────────────────────────────────────────────────────────────
# Registry: backend_type_string → (module_path, ClassName)
# ─────────────────────────────────────────────────────────────

_ADAPTER_REGISTRY: dict[str, tuple[str, str]] = {
    # Cloud API providers
    "gemini_native":         ("adapters.gemini_native",              "GeminiNativeAdapter"),
    "openai_compatible":     ("adapters.openai_compatible",          "OpenAICompatibleAdapter"),
    "anthropic":             ("adapters.anthropic_claude",           "AnthropicClaudeAdapter"),
    "azure_openai":          ("adapters.azure_openai",               "AzureOpenAIAdapter"),
    "groq":                  ("adapters.groq_api",                   "GroqAdapter"),
    "mistral":               ("adapters.mistral_api",                "MistralAdapter"),
    "together_ai":           ("adapters.together_ai",                "TogetherAIAdapter"),
    "huggingface_api":       ("adapters.huggingface_inference_api",  "HuggingFaceInferenceAPIAdapter"),

    "cohere":                ("adapters.cohere_command",             "CohereCommandAdapter"),

    # Local / self-hosted
    "ollama_local":          ("adapters.ollama_local",               "OllamaLocalAdapter"),
    "vllm_local":            ("adapters.vllm_local",                 "VLLMLocalAdapter"),
    "llamacpp_server":       ("adapters.llamacpp_server",            "LlamaCppServerAdapter"),
    "huggingface_local":     ("adapters.huggingface_local",          "HuggingFaceLocalAdapter"),
}

# Aliases for common alternate spellings
_ALIASES: dict[str, str] = {
    "gemini":            "gemini_native",
    "google":            "gemini_native",
    "openai":            "openai_compatible",
    "claude":            "anthropic",
    "azure":             "azure_openai",
    "hf":                "huggingface_local",
    "hf_api":            "huggingface_api",
    "huggingface":       "huggingface_local",
    "ollama":            "ollama_local",
    "vllm":              "vllm_local",
    "llamacpp":          "llamacpp_server",
    "llama_cpp":         "llamacpp_server",

    "together":          "together_ai",
}


def get_inference_adapter(backend_type: str | None = None) -> BaseAdapter:
    """
    Instantiate and return the configured inference adapter.

    Args:
        backend_type: Override AI_BACKEND_TYPE from settings (useful for testing).

    Returns:
        A fully initialised BaseAdapter subclass.

    Raises:
        ValueError: If the backend type is unknown.
        ImportError: If a required optional dependency is missing.
    """
    raw_type = (backend_type or settings.AI_BACKEND_TYPE or "").strip().lower()
    resolved = _ALIASES.get(raw_type, raw_type)

    if resolved not in _ADAPTER_REGISTRY:
        supported = "\n  ".join(sorted(_ADAPTER_REGISTRY.keys()))
        raise ValueError(
            f"Unknown AI_BACKEND_TYPE: '{raw_type}'\n\n"
            f"Supported backends:\n  {supported}\n\n"
            f"Set AI_BACKEND_TYPE in your .env file."
        )

    module_path, class_name = _ADAPTER_REGISTRY[resolved]

    try:
        import importlib
        module = importlib.import_module(module_path)
        adapter_class = getattr(module, class_name)
    except ImportError as exc:
        raise ImportError(
            f"Failed to import adapter '{resolved}' from '{module_path}'. "
            f"You may need to install additional dependencies.\n"
            f"Error: {exc}"
        ) from exc

    logger.info(
        "ADAPTER_INIT | backend=%s class=%s", resolved, class_name
    )
    return adapter_class()


def list_available_backends() -> list[str]:
    """Return all registered backend type strings (including aliases)."""
    return sorted(_ADAPTER_REGISTRY.keys())
