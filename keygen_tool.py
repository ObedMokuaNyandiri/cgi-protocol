"""
CGI Protocol — License Key Generator CLI v1.0
===============================================
YOUR private admin tool for issuing and revoking enterprise licenses.
NEVER distribute this file or the issuer_private.pem to clients.

Usage:
    python keygen_tool.py setup
    python keygen_tool.py issue --licensee "Acme Corp" --domain FINANCIAL --tier ENTERPRISE --days 365
    python keygen_tool.py issue --licensee "City Hospital" --domain MEDICAL --tier PROFESSIONAL --days 365
    python keygen_tool.py list
    python keygen_tool.py revoke --license-id lic-abc123
    python keygen_tool.py inspect --file path/to/license.json

License files issued here are given to clients, who place them in their
deployment directory and set CGI_LICENSE_KEY_PATH in their .env.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ── Bootstrap path ────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from config import settings


# ─────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────

ISSUER_PRIV_PATH = os.path.join(settings.AUTH_DIR, "issuer_private.pem")
ISSUER_PUB_PATH  = os.path.join(settings.AUTH_DIR, "issuer_public.pem")
REGISTRY_PATH    = os.path.join(settings.OUTPUT_DIR, "license_registry.json")
LICENSES_DIR     = os.path.join(settings.OUTPUT_DIR, "issued_licenses")


# ─────────────────────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────────────────────

def _g(t: str) -> str: return f"\033[32;1m{t}\033[0m"
def _r(t: str) -> str: return f"\033[31;1m{t}\033[0m"
def _c(t: str) -> str: return f"\033[36m{t}\033[0m"
def _b(t: str) -> str: return f"\033[1m{t}\033[0m"
def _d(t: str) -> str: return f"\033[2m{t}\033[0m"


# ─────────────────────────────────────────────────────────────
# Issuer Key Management
# ─────────────────────────────────────────────────────────────

def _setup_issuer_keypair() -> None:
    """Generate the issuer ECDSA key pair if it does not already exist."""
    os.makedirs(settings.AUTH_DIR, exist_ok=True)
    os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
    os.makedirs(LICENSES_DIR, exist_ok=True)

    if os.path.exists(ISSUER_PRIV_PATH):
        print(_g("✓") + f"  Issuer key pair already exists at {ISSUER_PRIV_PATH}")
        return

    print("Generating issuer ECDSA secp256k1 key pair...")
    key = ec.generate_private_key(ec.SECP256K1())

    # Save private key
    with open(ISSUER_PRIV_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    if os.name == "posix":
        os.chmod(ISSUER_PRIV_PATH, 0o600)

    # Save public key
    with open(ISSUER_PUB_PATH, "wb") as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(_g("✓") + f"  Private key : {ISSUER_PRIV_PATH}")
    print(_g("✓") + f"  Public key  : {ISSUER_PUB_PATH}")
    print()
    print(_b("  IMPORTANT:"))
    print("  • Keep " + _r("issuer_private.pem") + " SECRET. Never distribute it.")
    print("  • The public key path (" + _c(ISSUER_PUB_PATH) + ") must be set")
    print("    as ISSUER_PUBLIC_KEY_PATH in your .env")
    print("  • Deploy it inside your Docker image alongside api_gateway.py")

    # Initialise empty registry
    if not os.path.exists(REGISTRY_PATH):
        _save_registry({"licenses": [], "revoked": []})
        print(_g("✓") + f"  Registry     : {REGISTRY_PATH} (initialised)")


def _load_issuer_private_key() -> ec.EllipticCurvePrivateKey:
    if not os.path.exists(ISSUER_PRIV_PATH):
        print(_r("✗  Issuer private key not found."))
        print("   Run: python keygen_tool.py setup")
        sys.exit(1)
    with open(ISSUER_PRIV_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ─────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────

def _load_registry() -> dict:
    if not os.path.exists(REGISTRY_PATH):
        return {"licenses": [], "revoked": []}
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_registry(registry: dict) -> None:
    os.makedirs(os.path.dirname(REGISTRY_PATH), exist_ok=True)
    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)


# ─────────────────────────────────────────────────────────────
# License Token Builder
# ─────────────────────────────────────────────────────────────

_TIER_DEFAULTS = {
    "TRIAL": {
        "max_requests_per_day": 100, "max_requests_per_minute": 5,
        "allowed_models": ["gemini-2.5-flash-lite"],
        "blockchain_anchor": False, "audit_export": False,
        "max_prompt_length": 1024, "data_classifications": ["PUBLIC"],
    },
    "STARTER": {
        "max_requests_per_day": 2000, "max_requests_per_minute": 30,
        "allowed_models": ["gemini-2.5-flash", "gemini-2.5-flash-lite"],
        "blockchain_anchor": True, "audit_export": True,
        "max_prompt_length": 4096, "data_classifications": ["PUBLIC", "CONFIDENTIAL"],
    },
    "PROFESSIONAL": {
        "max_requests_per_day": 20000, "max_requests_per_minute": 200,
        "allowed_models": ["gemini-2.5-flash", "gemini-3.5-flash", "gemini-2.5-pro"],
        "blockchain_anchor": True, "audit_export": True,
        "max_prompt_length": 8192, "data_classifications": ["PUBLIC", "CONFIDENTIAL", "PII"],
    },
    "ENTERPRISE": {
        "max_requests_per_day": 500000, "max_requests_per_minute": 1000,
        "allowed_models": [],  # empty = all models
        "blockchain_anchor": True, "audit_export": True,
        "max_prompt_length": 32768,
        "data_classifications": ["PUBLIC", "CONFIDENTIAL", "PII", "PRIVILEGED", "CLASSIFIED"],
    },
}


def _sign_license(payload: dict, private_key: ec.EllipticCurvePrivateKey) -> str:
    """Sign canonical JSON payload and return base64-encoded signature."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig_bytes = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig_bytes).decode("utf-8")


def cmd_issue(args: argparse.Namespace) -> None:
    """Issue a new signed license token."""
    tier = args.tier.upper()
    if tier not in _TIER_DEFAULTS:
        print(_r(f"✗  Unknown tier '{tier}'. Choose: TRIAL, STARTER, PROFESSIONAL, ENTERPRISE"))
        sys.exit(1)

    private_key = _load_issuer_private_key()
    pub_key = private_key.public_key()
    pub_key_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    pub_fingerprint = "sha256:" + __import__("hashlib").sha256(pub_key_pem.encode()).hexdigest()[:16]

    now        = int(time.time())
    expires_at = now + (args.days * 86400)
    license_id = f"lic-{uuid.uuid4().hex[:16]}"

    tier_defaults = dict(_TIER_DEFAULTS[tier])

    payload = {
        "license_id":     license_id,
        "schema_version": "cgi-license-v1.0",
        "licensee": {
            "name":          args.licensee,
            "domain":        args.domain.upper(),
            "deployment_id": args.deployment_id or f"{args.licensee.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}",
        },
        "tier": tier,
        "features": tier_defaults,
        "validity": {
            "issued_at":            now,
            "expires_at":           expires_at,
            "grace_period_seconds": 86400,
        },
        "issuer": {
            "name":                   "CGI-Protocol Licensing",
            "public_key_fingerprint": pub_fingerprint,
            "contact":                "licensing@cgi-protocol.io",
        },
    }

    signature = _sign_license(payload, private_key)
    payload["signature"] = signature

    # Write license file
    os.makedirs(LICENSES_DIR, exist_ok=True)
    license_file = os.path.join(LICENSES_DIR, f"{license_id}.json")
    with open(license_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # Update registry
    registry = _load_registry()
    registry["licenses"].append({
        "license_id":    license_id,
        "licensee_name": args.licensee,
        "domain":        args.domain.upper(),
        "tier":          tier,
        "issued_at":     now,
        "expires_at":    expires_at,
        "expires_iso":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at)),
        "status":        "ACTIVE",
        "file":          license_file,
    })
    _save_registry(registry)

    # Also produce a compact, single-line license key string for easy delivery
    compact_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    compact_key = "CGI-" + base64.urlsafe_b64encode(compact_json.encode("utf-8")).decode("utf-8")

    print()
    print(_g("LICENSE ISSUED SUCCESSFULLY"))
    print()
    print(f"  {'License ID':<22} {license_id}")
    print(f"  {'Licensee':<22} {args.licensee}")
    print(f"  {'Domain':<22} {args.domain.upper()}")
    print(f"  {'Tier':<22} {tier}")
    print(f"  {'Expires':<22} {time.strftime('%Y-%m-%d', time.gmtime(expires_at))} ({args.days} days)")
    print(f"  {'Req/Day':<22} {tier_defaults['max_requests_per_day']:,}")
    print(f"  {'Req/Min':<22} {tier_defaults['max_requests_per_minute']}")
    print(f"  {'Blockchain Anchor':<22} {'YES' if tier_defaults['blockchain_anchor'] else 'NO'}")
    print()
    print(_b("  ════════════════════════════════════════════════════════"))
    print(_b("  LICENSE KEY (send this to the client)"))
    print(_b("  ════════════════════════════════════════════════════════"))
    print()
    # Print the key in 72-char chunks for readability
    for i in range(0, len(compact_key), 72):
        print(f"  {compact_key[i:i+72]}")
    print()
    print(_b("  ════════════════════════════════════════════════════════"))
    print()
    print(_b("  Client Activation (one command):"))
    print(f"  curl -X POST http://localhost:8000/v1/license/activate \\")
    print(f"    -H 'Content-Type: application/json' \\")
    print(f"    -d '{{\"license_key\": \"<paste key above>\"}}' ")
    print()
    print(_d("  Or via the CGI Protocol Dashboard -> License tab -> Paste & Activate"))
    print()
    print(f"  JSON file also saved: {_c(license_file)}")
    print()


def cmd_revoke(args: argparse.Namespace) -> None:
    """Add a license to the revocation list."""
    registry = _load_registry()
    found = False
    for entry in registry["licenses"]:
        if entry["license_id"] == args.license_id:
            entry["status"] = "REVOKED"
            found = True
    if not found:
        print(_r(f"✗  License ID '{args.license_id}' not found in registry."))
        sys.exit(1)

    if args.license_id not in registry["revoked"]:
        registry["revoked"].append(args.license_id)
    _save_registry(registry)

    print(_g("✓") + f"  License {args.license_id} has been revoked.")
    print(_d("  Clients checking revocation will be blocked at next renewal check."))


def cmd_list(args: argparse.Namespace) -> None:
    """List all issued licenses."""
    registry = _load_registry()
    licenses = registry.get("licenses", [])
    if not licenses:
        print(_d("  No licenses have been issued yet."))
        return

    now = time.time()
    print()
    print(_b(f"  {'LICENSE ID':<22} {'LICENSEE':<24} {'TIER':<14} {'STATUS':<10} {'EXPIRES'}"))
    print("  " + "─" * 80)
    for lic in licenses:
        expired = lic["expires_at"] < now
        status  = lic.get("status", "ACTIVE")
        if status == "REVOKED":
            status_label = _r("REVOKED")
        elif expired:
            status_label = _r("EXPIRED")
        else:
            status_label = _g("ACTIVE")
        print(f"  {lic['license_id']:<22} {lic['licensee_name']:<24} {lic['tier']:<14} {status_label:<20} {lic['expires_iso']}")
    print()


def cmd_inspect(args: argparse.Namespace) -> None:
    """Inspect a license file and verify its signature."""
    if not os.path.exists(args.file):
        print(_r(f"✗  File not found: {args.file}"))
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Attempt signature verification
    sig_valid = None
    if os.path.exists(ISSUER_PUB_PATH):
        from license_manager import LicenseManager
        manager = LicenseManager(ISSUER_PUB_PATH)
        sig_valid = manager._verify_signature(data)

    now        = time.time()
    expires_at = data.get("validity", {}).get("expires_at", 0)
    expired    = expires_at < now

    print()
    print(_b("  CGI-Protocol License Inspector"))
    print("  " + "─" * 50)
    print(f"  License ID   : {data.get('license_id', 'N/A')}")
    print(f"  Schema       : {data.get('schema_version', 'N/A')}")
    licensee = data.get("licensee", {})
    print(f"  Licensee     : {licensee.get('name', 'N/A')}")
    print(f"  Domain       : {licensee.get('domain', 'N/A')}")
    print(f"  Tier         : {data.get('tier', 'N/A')}")
    print(f"  Issued       : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(data.get('validity',{}).get('issued_at',0)))}")
    print(f"  Expires      : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expires_at))} {'(' + _r('EXPIRED') + ')' if expired else '(' + _g('VALID') + ')'}")
    if sig_valid is not None:
        sv = _g("✓ VALID") if sig_valid else _r("✗ INVALID — TAMPERED OR FORGED")
        print(f"  Signature    : {sv}")
    print()
    features = data.get("features", {})
    print(f"  Req/Day      : {features.get('max_requests_per_day', 'N/A'):,}" if isinstance(features.get('max_requests_per_day'), int) else f"  Req/Day      : {features.get('max_requests_per_day', 'N/A')}")
    print(f"  Req/Min      : {features.get('max_requests_per_minute', 'N/A')}")
    print(f"  Anchor       : {'YES' if features.get('blockchain_anchor') else 'NO'}")
    classifications = features.get('data_classifications', [])
    print(f"  Data Classes : {', '.join(classifications)}")
    print()


# ─────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CGI-Protocol License Key Generator — issue, revoke, and inspect license tokens.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python keygen_tool.py setup
  python keygen_tool.py issue --licensee "Acme Corp" --domain FINANCIAL --tier ENTERPRISE --days 365
  python keygen_tool.py issue --licensee "City Hospital" --domain MEDICAL --tier PROFESSIONAL --days 365
  python keygen_tool.py list
  python keygen_tool.py revoke --license-id lic-abc123def456
  python keygen_tool.py inspect --file outputs/issued_licenses/lic-abc123.json
""",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    sub.add_parser("setup", help="Generate the issuer key pair (run once)")

    # issue
    p_issue = sub.add_parser("issue", help="Issue a new signed license token")
    p_issue.add_argument("--licensee",      required=True, help="Organization name, e.g. 'Acme Corp'")
    p_issue.add_argument("--domain",        required=True, help="Domain: MEDICAL | LEGAL | FINANCIAL | GOVERNMENT | GENERAL")
    p_issue.add_argument("--tier",          required=True, help="Tier: TRIAL | STARTER | PROFESSIONAL | ENTERPRISE")
    p_issue.add_argument("--days",          type=int, default=365, help="License validity in days (default: 365)")
    p_issue.add_argument("--deployment-id", dest="deployment_id", default="", help="Optional deployment identifier")

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke an issued license")
    p_revoke.add_argument("--license-id", required=True, dest="license_id")

    # list
    sub.add_parser("list", help="List all issued licenses")

    # inspect
    p_inspect = sub.add_parser("inspect", help="Inspect and verify a license file")
    p_inspect.add_argument("--file", required=True)

    args = parser.parse_args()

    if args.command == "setup":
        _setup_issuer_keypair()
    elif args.command == "issue":
        cmd_issue(args)
    elif args.command == "revoke":
        cmd_revoke(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "inspect":
        cmd_inspect(args)


if __name__ == "__main__":
    main()
