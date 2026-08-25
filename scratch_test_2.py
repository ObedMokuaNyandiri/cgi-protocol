import sys
import os

# Add the project root to the path so we can import adapters
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import settings
from adapters.gemini_native import GeminiNativeAdapter

def test_wrapper():
    print("Testing Gemini Native Adapter with config from .env")
    
    adapter = GeminiNativeAdapter()
    
    print("\n--- Running Generation Test (max_tokens=500) ---")
    prompt = "Hello, are you there? Please reply with 'Yes, I am production ready'."
    
    try:
        text, stop, tokens = adapter.generate(
            prompt=prompt,
            max_tokens=500,
            execution_id="test_prod_02",
            seed=0
        )
        print(f"\nGenerated text:\n{text}")
        print(f"\nStop reason: {stop}")
        print(f"Token count: {tokens}")
    except Exception as e:
        print(f"\nGeneration failed: {e}")

if __name__ == '__main__':
    test_wrapper()
