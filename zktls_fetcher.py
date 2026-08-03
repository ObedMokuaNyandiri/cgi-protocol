import hashlib
import time
from typing import Any


def fetch_with_zktls(url: str, temporal_block_hash: str) -> tuple[dict[str, Any], str]:
    """
    Simulates a Zero-Knowledge TLS (zk-TLS) fetch of an external API.
    In a real zk-TLS setup (like TLSNotary), the client proves that the data 
    came from the specific HTTPS server at a specific time, without relying on a central oracle.
    
    TEMPORAL ANCHORING: The `temporal_block_hash` acts as the `ClientHello.random`.
    This proves mathematically that the TLS connection was established AFTER the block was mined,
    preventing Time-Travel MEV (stale oracle replay attacks).
    """
    print(f"[ZK-TLS] Connecting to {url} via Zero-Knowledge TLS circuit...")
    print(f"  -> Using L1 Temporal Anchor: {temporal_block_hash[:16]}...")
    time.sleep(1) # Simulate handshake and proof generation
    
    # Mocked payload from the API
    if "bloomberg" in url:
        data = {
            "symbol": "AAPL",
            "price": 185.50,
            "currency": "USD",
            "timestamp": int(time.time()),
            "status": "MARKET_OPEN"
        }
    else:
        data = {
            "status": "ok",
            "timestamp": int(time.time())
        }
    
    print(f"[ZK-TLS] Verified cryptographic signature from {url.split('//')[1].split('/')[0]}")
    
    # Generate the cryptographic provenance hash (the proof)
    payload_str = str(data)
    # The proof mathematically binds the payload to the specific L1 blockhash
    zktls_proof_hash = hashlib.sha256(f"zktls|{url}|{payload_str}|{temporal_block_hash}".encode()).hexdigest()
    
    return data, zktls_proof_hash
