"""
Adapter Architecture for AI Backends
Allows the CGI-Protocol to act as a cryptographic wrapper around local or external enterprise AI models.
"""

from config import settings

class BaseAdapter:
    def generate(self, prompt: str, max_tokens: int, execution_id: str, seed: int) -> tuple[str, str, int]:
        """
        Returns (generated_text, stop_reason, token_count)
        """
        raise NotImplementedError

def get_inference_adapter() -> BaseAdapter:
    if settings.AI_BACKEND_TYPE == "openai_compatible":
        from adapters.openai_compatible import OpenAICompatibleAdapter
        return OpenAICompatibleAdapter()
    elif settings.AI_BACKEND_TYPE == "huggingface_local":
        from adapters.huggingface_local import HuggingFaceLocalAdapter
        return HuggingFaceLocalAdapter()
    else:
        raise ValueError(f"Unknown AI_BACKEND_TYPE: {settings.AI_BACKEND_TYPE}")
