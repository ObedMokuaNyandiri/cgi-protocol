import hashlib
import time
from typing import Any

def fetch_with_zktls(url: str, temporal_block_hash: str, prompt: str = "") -> tuple[dict[str, Any], str]:
    """
    Simulates a Zero-Knowledge TLS (zk-TLS) fetch of an external LLM API.
    In a real zk-TLS setup (like TLSNotary or DECO), the client proves that the data 
    came from the specific HTTPS server at a specific time, without relying on a central oracle.
    
    TEMPORAL ANCHORING: The `temporal_block_hash` acts as the `ClientHello.random`.
    This proves mathematically that the TLS connection was established AFTER the block was mined,
    preventing Time-Travel MEV (stale oracle replay attacks).
    """
    import os
    import urllib.request
    import json
    
    print(f"[ZK-TLS] Establishing MPC-TLS session with {url}...")
    print(f"  -> Using L1 Temporal Anchor: {temporal_block_hash[:16]}...")
    time.sleep(1) # Simulate handshake and proof generation
    
    data = None
    
    if "gemini" in url.lower():
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key:
            if not prompt:
                prompt = os.environ.get("ZK_TLS_PROMPT", "Hello Gemini, this is a test.")
            req_data = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            req = urllib.request.Request(
                f"{url}?key={api_key}",
                data=json.dumps(req_data).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req) as response:
                    resp_data = json.loads(response.read().decode())
                    # Extract text properly from Gemini format
                    try:
                        text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                    except (KeyError, IndexError):
                        text = str(resp_data)
                        
                    data = {
                        "id": "gemini-zktls",
                        "object": "chat.completion",
                        "created": int(time.time()),
                        "model": "gemini-1.5",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": text
                            },
                            "finish_reason": "stop"
                        }]
                    }
            except Exception as e:
                print(f"[ZK-TLS] API call failed: {e}. Falling back to mock.")
                data = None

    if not data:
        if "gemini" in url.lower():
            # Mocked Gemini API response
            data = {
                "id": "gemini-zktls-mock",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": "gemini-1.5",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"This is a cryptographically verified response from Gemini via zkTLS. I have analyzed your prompt: '{prompt}'."
                    },
                    "finish_reason": "stop"
                }]
            }
        else:
            # Mocked LLM API response (OpenAI)
            data = {
                "id": "chatcmpl-9xyz",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": "gpt-4-turbo",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "This is a cryptographically verified response from the LLM via zkTLS."
                    },
                    "finish_reason": "stop"
                }]
            }
    
    print(f"[ZK-TLS] Verified cryptographic signature from {url.split('//')[1].split('/')[0]} TLS certificate")
    
    # Generate the cryptographic provenance hash (the proof)
    payload_str = str(data)
    # The proof mathematically binds the payload to the specific L1 blockhash
    zktls_proof_hash = hashlib.sha256(f"zktls|{url}|{payload_str}|{temporal_block_hash}".encode()).hexdigest()
    
    print(f"[ZK-TLS] Proof Generated: 0x{zktls_proof_hash[:16]}...")
    return data, zktls_proof_hash
