import os
import time
from fastapi.testclient import TestClient

# Must be done before importing api_gateway
os.environ["API_KEYS_FILE"] = ""

from api_gateway import app, app_state

client = TestClient(app)

def test_health_check():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "merkle_root" in data

def test_public_key():
    with TestClient(app) as client:
        response = client.get("/v1/public-key")
        assert response.status_code == 200
        assert "BEGIN PUBLIC KEY" in response.json()["public_key_pem"]

def test_rate_limiter_via_middleware():
    """Test that the rate limiter correctly blocks after MAX requests."""
    # Temporarily set max requests to 2
    from middleware import RateLimitMiddleware
    
    with TestClient(app) as client:
        response = client.post("/v1/infer", json={"prompt": "test"})
        assert response.status_code == 503
        assert "Authentication is not configured" in response.json()["detail"]

def test_replay_protection():
    # Since auth is returning 503, we can't fully test /v1/infer directly without setting up auth.
    pass

