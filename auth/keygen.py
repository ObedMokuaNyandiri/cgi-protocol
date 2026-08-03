#!/usr/bin/env python3
"""
CGI Protocol — Governance Key & API Key Generator
====================================================
Standalone script to generate:
  1. ECDSA secp256k1 governance key pair (for signing attestations)
  2. API keys (for authenticating API requests)

Usage:
    python auth/keygen.py                    # Generate governance keys
    python auth/keygen.py --api-key          # Generate a new API key
    python auth/keygen.py --api-key "org"    # Generate API key with org name
"""

import hashlib
import json
import os
import sys
import uuid


def generate_governance_keys(auth_dir: str = None) -> None:
    """Generate ECDSA secp256k1 governance key pair."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if auth_dir is None:
        auth_dir = os.path.dirname(os.path.abspath(__file__))

    priv_path = os.path.join(auth_dir, "private_key.pem")
    pub_path = os.path.join(auth_dir, "public_key.pem")

    if os.path.exists(priv_path):
        print(f"[!] Private key already exists at: {priv_path}")
        resp = input("    Overwrite? (y/N): ").strip().lower()
        if resp != "y":
            print("    Aborted.")
            return

    key = ec.generate_private_key(ec.SECP256K1())

    # Write private key
    with open(priv_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Set restrictive permissions on Unix
    if os.name == "posix":
        os.chmod(priv_path, 0o600)

    # Write public key
    pub_key = key.public_key()
    with open(pub_path, "wb") as f:
        f.write(pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    # Compute fingerprint
    pub_der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(pub_der).hexdigest()

    print("\n[OK] Governance key pair generated:")
    print(f"  Private: {priv_path}")
    print(f"  Public:  {pub_path}")
    print(f"  Fingerprint: {fingerprint}")
    print("\n[!] NEVER commit private_key.pem to source control!")


def generate_api_key(organization: str = "default") -> None:
    """Generate a random API key and add it to the api_keys.json file."""
    auth_dir = os.path.dirname(os.path.abspath(__file__))
    keys_file = os.path.join(auth_dir, "api_keys.json")

    # Generate random key
    raw_key = os.urandom(32).hex()
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    key_id = f"{organization.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"

    # Load existing keys
    if os.path.exists(keys_file):
        with open(keys_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {"keys": []}

    # Add new key
    data["keys"].append({
        "key_id": key_id,
        "key_hash": key_hash,
        "scopes": ["infer", "audit"],
        "organization": organization,
        "active": True,
    })

    # Save
    with open(keys_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print("\n[OK] API key generated:")
    print(f"  Key ID:       {key_id}")
    print(f"  Organization: {organization}")
    print("  Scopes:       infer, audit")
    print()
    print(f"  +{'=' * 68}+")
    print(f"  |  API KEY: {raw_key}  |")
    print(f"  +{'=' * 68}+")
    print()
    print("  Save this key NOW — it will not be shown again!")
    print(f"  Use it in requests: curl -H 'X-API-Key: {raw_key}' ...")


if __name__ == "__main__":
    if "--api-key" in sys.argv:
        org = "Default Organization"
        idx = sys.argv.index("--api-key")
        if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("--"):
            org = sys.argv[idx + 1]
        generate_api_key(org)
    else:
        generate_governance_keys()
