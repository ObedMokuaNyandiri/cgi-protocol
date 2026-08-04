import json
import logging
import urllib.request
from typing import Tuple
from config import settings
from adapters import BaseAdapter

logger = logging.getLogger("cgi.adapters.openai")

class OpenAICompatibleAdapter(BaseAdapter):
    def generate(self, prompt: str, max_tokens: int, execution_id: str, seed: int) -> Tuple[str, str, int]:
        if not settings.AI_ENDPOINT_URL:
            raise ValueError("AI_ENDPOINT_URL must be configured for openai_compatible backend")
            
        url = f"{settings.AI_ENDPOINT_URL.rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json"
        }
        if settings.AI_API_KEY:
            headers["Authorization"] = f"Bearer {settings.AI_API_KEY}"
            
        payload = {
            "model": settings.MODEL_ID,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a controlled inference engine. Answer in 3-5 precise sentences. Respond with technical precision."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": max_tokens,
            "temperature": settings.DEFAULT_TEMPERATURE,
            "seed": seed
        }
        
        req = urllib.request.Request(
            url, 
            data=json.dumps(payload).encode("utf-8"), 
            headers=headers, 
            method="POST"
        )
        
        try:
            with urllib.request.urlopen(req, timeout=settings.WORKER_TIMEOUT_SECONDS) as response:
                result = json.loads(response.read().decode("utf-8"))
                
            choice = result.get("choices", [{}])[0]
            generated_text = choice.get("message", {}).get("content", "")
            stop_reason = choice.get("finish_reason", "unknown")
            token_count = result.get("usage", {}).get("completion_tokens", 0)
            
            return generated_text, stop_reason, token_count
            
        except Exception as e:
            logger.error("OpenAI API error: %s", e)
            raise RuntimeError(f"External AI model failed: {str(e)}")
