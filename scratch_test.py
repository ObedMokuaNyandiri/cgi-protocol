import sys
import os
import json
import urllib.request

# Add the project root to the path so we can import adapters
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import settings
from adapters.gemini_native import GeminiNativeAdapter

def test_wrapper():
    print("Testing Gemini Native Adapter with config from .env")
    
    adapter = GeminiNativeAdapter()
    
    prompt = "Hello, are you there? Please reply with 'Yes, I am production ready'."
    max_tokens = 50
    
    # Do it manually to see raw response
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{adapter._model_id}:generateContent?key={adapter._api_key}"
    body = adapter._build_request_body(prompt, max_tokens)
    print(f"Request body: {json.dumps(body, indent=2)}")
    
    req_bytes = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=req_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    
    try:
        with urllib.request.urlopen(request, timeout=adapter._timeout) as response:
            raw = json.loads(response.read().decode("utf-8"))
            print(f"Raw response: {json.dumps(raw, indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    test_wrapper()
