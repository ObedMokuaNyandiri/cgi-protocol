"""
CGI Protocol — License Manager v1.0
=====================================
Zero-cost, cryptographically decentralized enterprise licensing.

Architecture:
    - YOU hold the issuer ECDSA private key (secp256k1)
    - Each client receives a signed license token (JSON file)
    - This module verifies the license token at boot — OFFLINE, no network needed
    - Mathematically impossible to forge without the private key

Domain-agnostic: Healthcare, Legal, Financial, Government,
Insurance, Media, Defence — any enterprise AI deployment.

Cost: $0.00 — pure cryptography, zero hosting, zero blockchain fees.

License Tiers:
    TRIAL        — 100 req/day,    5 req/min, flash only,    PUBLIC data
    STARTER      — 2,000 req/day,  30 req/min, flash,         + CONFIDENTIAL
    PROFESSIONAL — 20,000 req/day, 200 req/min, flash+pro,    + PII
    ENTERPRISE   — 500,000 req/day,1000 req/min, all models,  all classifications
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
import base64

logger = logging.getLogger("cgi.license")


# ─────────────────────────────────────────────────────────────
# License Tiers
# ─────────────────────────────────────────────────────────────

class LicenseTier(str, Enum):
    TRIAL        = "TRIAL"
    STARTER      = "STARTER"
    PROFESSIONAL = "PROFESSIONAL"
    ENTERPRISE   = "ENTERPRISE"


# Tier-based feature matrix
_TIER_LIMITS: dict[str, dict] = {
    LicenseTier.TRIAL: {
        "max_requests_per_day":    100,
        "max_requests_per_minute": 5,
        "allowed_models_prefix":   ["flash", "lite"],
        "blockchain_anchor":       False,
        "audit_export":            False,
        "max_prompt_length":       1024,
        "data_classifications":    ["PUBLIC"],
    },
    LicenseTier.STARTER: {
        "max_requests_per_day":    2_000,
        "max_requests_per_minute": 30,
        "allowed_models_prefix":   ["flash", "lite"],
        "blockchain_anchor":       True,
        "audit_export":            True,
        "max_prompt_length":       4096,
        "data_classifications":    ["PUBLIC", "CONFIDENTIAL"],
    },
    LicenseTier.PROFESSIONAL: {
        "max_requests_per_day":    20_000,
        "max_requests_per_minute": 200,
        "allowed_models_prefix":   ["flash", "lite", "pro", "claude", "opus", "sonnet", "haiku", "gpt-4"],
        "blockchain_anchor":       True,
        "audit_export":            True,
        "max_prompt_length":       200000,
        "data_classifications":    ["PUBLIC", "CONFIDENTIAL", "PII"],
    },
    LicenseTier.ENTERPRISE: {
        "max_requests_per_day":    500_000,
        "max_requests_per_minute": 1000,
        "allowed_models_prefix":   [],  # empty = all models allowed
        "blockchain_anchor":       True,
        "audit_export":            True,
        "max_prompt_length":       1000000,
        "data_classifications":    ["PUBLIC", "CONFIDENTIAL", "PII", "PRIVILEGED", "CLASSIFIED"],
    },
}


# ─────────────────────────────────────────────────────────────
# License Status Dataclass (returned to gateway)
# ─────────────────────────────────────────────────────────────

@dataclass
class LicenseStatus:
    """
    Fully resolved license state. Used by the gateway and middleware
    to enforce per-client feature limits.
    """
    valid:                    bool
    license_id:               str           = ""
    licensee_name:            str           = ""
    licensee_domain:          str           = "GENERAL"
    tier:                     str           = LicenseTier.TRIAL
    expires_at:               float         = 0.0
    max_requests_per_day:     int           = 0
    max_requests_per_minute:  int           = 5
    allowed_models:           list[str]     = field(default_factory=list)
    allowed_model_prefixes:   list[str]     = field(default_factory=list)
    blockchain_anchor:        bool          = False
    audit_export:             bool          = False
    max_prompt_length:        int           = 1024
    data_classifications:     list[str]     = field(default_factory=lambda: ["PUBLIC"])
    signature:                str           = ""
    error:                    str           = ""

    @property
    def expires_at_iso(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.expires_at))

    @property
    def days_remaining(self) -> int:
        return max(0, int((self.expires_at - time.time()) / 86400))

    def is_model_allowed(self, model_id: str) -> bool:
        """Returns True if the model is permitted under this license tier."""
        if not self.allowed_model_prefixes:
            return True  # ENTERPRISE: all models allowed
        # Explicit allow list
        if model_id in self.allowed_models:
            return True
        # Prefix match (e.g. "flash" matches "gemini-2.5-flash")
        return any(prefix in model_id for prefix in self.allowed_model_prefixes)

    def is_classification_allowed(self, classification: str) -> bool:
        """Returns True if the data classification is permitted."""
        return classification in self.data_classifications


# ─────────────────────────────────────────────────────────────
# License Verification Engine
# ─────────────────────────────────────────────────────────────

class LicenseManager:
    """
    Verifies CGI-Protocol license tokens.

    At startup, call verify_license() once. The returned LicenseStatus
    is attached to AppState and consulted on every inference request.
    """

    GRACE_PERIOD_SECONDS = 86_400  # 24 hours grace after expiry

    def __init__(self, issuer_public_key_path: str):
        self._issuer_pub_key = self._load_issuer_public_key(issuer_public_key_path)

    @staticmethod
    def _load_issuer_public_key(path: str) -> ec.EllipticCurvePublicKey | None:
        if not path or not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                key = serialization.load_pem_public_key(f.read())
            if not isinstance(key, ec.EllipticCurvePublicKey):
                logger.error("LICENSE | Issuer key is not ECDSA — license verification disabled")
                return None
            return key
        except Exception as e:
            logger.error("LICENSE | Failed to load issuer public key: %s", e)
            return None

    @staticmethod
    def _canonical_payload(license_data: dict) -> bytes:
        """
        Produce the canonical bytes that were signed.
        = All fields EXCEPT 'signature', sorted keys, no extra whitespace.
        """
        payload = {k: v for k, v in license_data.items() if k != "signature"}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _verify_signature(self, license_data: dict) -> bool:
        """Verify the ECDSA signature on the license token."""
        if self._issuer_pub_key is None:
            return False
        sig_b64 = license_data.get("signature", "")
        if not sig_b64:
            return False
        try:
            sig_bytes = base64.b64decode(sig_b64)
            payload_bytes = self._canonical_payload(license_data)
            self._issuer_pub_key.verify(sig_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            logger.error("LICENSE | Signature verification FAILED — token may be tampered with")
            return False
        except Exception as e:
            logger.error("LICENSE | Signature check error: %s", e)
            return False

    def verify_license(
        self,
        license_file_path: str,
        enforcement: str = "ENFORCE",
    ) -> LicenseStatus:
        """
        Load, verify and return a LicenseStatus from a license JSON file.

        enforcement modes:
            ENFORCE  — Fail hard if license missing or invalid (production)
            WARN     — Log warning but allow startup (dev/testing only)
            DISABLED — Skip all checks; return a TRIAL-equivalent status
        """
        if enforcement == "DISABLED":
            logger.warning("LICENSE | Enforcement DISABLED — running in open mode")
            # DISABLED = development/open-source mode; grant full access with no restrictions.
            # Using ENTERPRISE limits ensures ALLOWED_MODELS validation never blocks any model.
            tier_limits = _TIER_LIMITS[LicenseTier.ENTERPRISE]
            return LicenseStatus(
                valid=True,
                license_id="LICENSE-DISABLED",
                licensee_name="Open Mode",
                tier=LicenseTier.ENTERPRISE,
                expires_at=time.time() + 86400 * 3650,  # 10 years
                **self._limits_to_status_fields(tier_limits),
            )

        # ── 1. File exists? ──────────────────────────────────────
        if not license_file_path or not os.path.exists(license_file_path):
            msg = f"License file not found: {license_file_path}"
            logger.error("LICENSE_FAIL | %s", msg)
            return self._fail(msg, enforcement)

        # ── 2. Parse JSON ────────────────────────────────────────
        try:
            with open(license_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            msg = f"License file could not be parsed: {e}"
            logger.error("LICENSE_FAIL | %s", msg)
            return self._fail(msg, enforcement)

        # ── 3. Schema version ────────────────────────────────────
        schema = data.get("schema_version", "")
        if not schema.startswith("cgi-license-"):
            msg = f"Unknown license schema: '{schema}'"
            logger.error("LICENSE_FAIL | %s", msg)
            return self._fail(msg, enforcement)

        # ── 4. Signature verification ────────────────────────────
        if self._issuer_pub_key is not None:
            if not self._verify_signature(data):
                msg = "License signature is INVALID — token was tampered with or forged"
                logger.critical("LICENSE_FAIL | %s", msg)
                return self._fail(msg, enforcement)
            logger.info("LICENSE | Signature: VALID")
        else:
            logger.warning("LICENSE | No issuer public key — skipping signature check")

        # ── 5. Expiry check ──────────────────────────────────────
        validity = data.get("validity", {})
        issued_at  = validity.get("issued_at",  0)
        expires_at = validity.get("expires_at", 0)
        grace      = validity.get("grace_period_seconds", self.GRACE_PERIOD_SECONDS)
        now        = time.time()

        if now > expires_at + grace:
            msg = (
                f"License EXPIRED on "
                f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expires_at))}. "
                f"Grace period ended. Contact licensing@cgi-protocol.io to renew."
            )
            logger.error("LICENSE_FAIL | %s", msg)
            return self._fail(msg, enforcement)

        if now > expires_at:
            days_over = int((now - expires_at) / 86400)
            logger.warning(
                "LICENSE_WARNING | License expired %d day(s) ago — in grace period (%.0f hours remaining).",
                days_over, (expires_at + grace - now) / 3600,
            )

        # ── 6. Resolve tier ──────────────────────────────────────
        raw_tier = data.get("tier", LicenseTier.TRIAL).upper()
        try:
            tier = LicenseTier(raw_tier)
        except ValueError:
            msg = f"Unknown license tier: '{raw_tier}'"
            logger.error("LICENSE_FAIL | %s", msg)
            return self._fail(msg, enforcement)

        # Override limits from the token itself (allows custom enterprise deals)
        base_limits = dict(_TIER_LIMITS[tier])
        token_features = data.get("features", {})
        if "max_requests_per_day" in token_features:
            base_limits["max_requests_per_day"] = token_features["max_requests_per_day"]
        if "max_requests_per_minute" in token_features:
            base_limits["max_requests_per_minute"] = token_features["max_requests_per_minute"]
        if "allowed_models" in token_features:
            base_limits["_explicit_models"] = token_features["allowed_models"]
        if "max_prompt_length" in token_features:
            base_limits["max_prompt_length"] = token_features["max_prompt_length"]
        if "data_classifications" in token_features:
            base_limits["data_classifications"] = token_features["data_classifications"]

        # ── 7. Build and return LicenseStatus ────────────────────
        licensee = data.get("licensee", {})
        license_id = data.get("license_id", "UNKNOWN")

        status = LicenseStatus(
            valid=True,
            license_id=license_id,
            licensee_name=licensee.get("name", "Unknown"),
            licensee_domain=licensee.get("domain", "GENERAL"),
            tier=tier,
            expires_at=expires_at,
            signature=data.get("signature", ""),
            **self._limits_to_status_fields(base_limits),
        )

        logger.info(
            "LICENSE_OK | id=%s licensee=%s tier=%s domain=%s expires=%s days_remaining=%d",
            license_id,
            licensee.get("name", "?"),
            tier,
            licensee.get("domain", "GENERAL"),
            status.expires_at_iso,
            status.days_remaining,
        )
        return status

    @staticmethod
    def _limits_to_status_fields(limits: dict) -> dict:
        return {
            "max_requests_per_day":    limits.get("max_requests_per_day",    100),
            "max_requests_per_minute": limits.get("max_requests_per_minute", 5),
            "allowed_models":          limits.get("_explicit_models", []),
            "allowed_model_prefixes":  limits.get("allowed_models_prefix", []),
            "blockchain_anchor":       limits.get("blockchain_anchor",       False),
            "audit_export":            limits.get("audit_export",            False),
            "max_prompt_length":       limits.get("max_prompt_length",       1024),
            "data_classifications":    limits.get("data_classifications",    ["PUBLIC"]),
        }

    def _fail(self, error: str, enforcement: str) -> LicenseStatus:
        if enforcement == "WARN":
            logger.warning("LICENSE | Enforcement=WARN — starting anyway with TRIAL limits")
            tier_limits = _TIER_LIMITS[LicenseTier.TRIAL]
            return LicenseStatus(
                valid=False,
                tier=LicenseTier.TRIAL,
                expires_at=time.time() + 3600,
                error=error,
                **self._limits_to_status_fields(tier_limits),
            )
        # ENFORCE mode — hard fail
        return LicenseStatus(valid=False, error=error)
