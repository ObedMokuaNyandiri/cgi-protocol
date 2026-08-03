import base64
import json
import os
import time

from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TOKEN_PATH = os.environ.get("CGI_TOKEN_PATH", os.path.join(BASE_DIR, "epoch_token.json"))
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "public_key.pem")


# ------------------------------------------------------------
# Core verification function
# ------------------------------------------------------------
def verify_token():
    print("[DEBUG] entering verify_token")

    print(f"[DEBUG] TOKEN_PATH = {TOKEN_PATH}")
    print(f"[DEBUG] PUBLIC_KEY_PATH = {PUBLIC_KEY_PATH}")

    if not os.path.exists(TOKEN_PATH):
        print("[ERROR] NO TOKEN FOUND")
        return False

    try:
        with open(TOKEN_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except Exception as e:
        print(f"[ERROR] FAILED TO READ TOKEN FILE: {e}")
        return False

    if not content:
        print("[ERROR] EMPTY TOKEN FILE")
        return False

    try:
        artifact = json.loads(content)
    except Exception as e:
        print(f"[ERROR] INVALID TOKEN JSON: {e}")
        return False

    if not isinstance(artifact, dict):
        print("[ERROR] MALFORMED TOKEN STRUCTURE")
        return False

    if "token" not in artifact or "signature" not in artifact:
        print("[ERROR] MALFORMED TOKEN: missing required fields")
        return False

    token = artifact["token"]

    if not isinstance(token, dict):
        print("[ERROR] TOKEN PAYLOAD INVALID")
        return False

    # ------------------------------------------------------------
    # Decode signature
    # ------------------------------------------------------------
    try:
        signature = base64.b64decode(artifact["signature"])
    except Exception as e:
        print(f"[ERROR] INVALID SIGNATURE ENCODING: {e}")
        return False

    # ------------------------------------------------------------
    # Rebuild canonical payload (must match generator exactly)
    # ------------------------------------------------------------
    try:
        payload = json.dumps(
            token,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")
    except Exception as e:
        print(f"[ERROR] FAILED TO SERIALIZE TOKEN: {e}")
        return False

    # ------------------------------------------------------------
    # Load public key
    # ------------------------------------------------------------
    if not os.path.exists(PUBLIC_KEY_PATH):
        print("[ERROR] PUBLIC KEY NOT FOUND")
        return False

    try:
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except Exception as e:
        print(f"[ERROR] FAILED TO LOAD PUBLIC KEY: {e}")
        return False

    # ------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------
    try:
        public_key.verify(signature, payload)
        print("[DEBUG] signature verification passed")
    except Exception as e:
        print(f"[ERROR] INVALID SIGNATURE: {e}")
        return False

    # ------------------------------------------------------------
    # Expiration validation
    # ------------------------------------------------------------
    expires = token.get("expires")
    if expires is None:
        print("[ERROR] TOKEN MISSING EXPIRES")
        return False

    if not isinstance(expires, (int, float)):
        print("[ERROR] INVALID EXPIRES TYPE")
        return False

    if expires < time.time():
        print("[ERROR] TOKEN EXPIRED")
        return False

    # ------------------------------------------------------------
    # Scope validation
    # ------------------------------------------------------------
    scope = token.get("scope")
    if scope is None:
        print("[ERROR] TOKEN MISSING SCOPE")
        return False

    if scope != "epoch_execution":
        print("[ERROR] INVALID SCOPE")
        return False

    print("[DEBUG] token validation successful")
    return True


# ------------------------------------------------------------
# Helper: load token payload only (no validation)
# ------------------------------------------------------------
def get_token():
    if not os.path.exists(TOKEN_PATH):
        return None

    try:
        with open(TOKEN_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("token")
    except Exception:
        return None