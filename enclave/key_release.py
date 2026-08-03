"""
CGI Protocol — Key Release Service (Software + Hardware modes)
================================================================
Software mode:  Loads the governance key directly from disk with
                measurement verification (self-signed attestation).
Hardware mode:  Validates CBOR/COSE attestation from Nitro NSM.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Optional

logger = logging.getLogger("cgi.kms")

_ENCLAVE_MODE = os.environ.get("ENCLAVE_MODE", "software")

# Resolve BASE_DIR to the project root (parent of enclave/)
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class RemoteKMS:
    """
    Key Management Service that releases the governance private key
    only if the attestation quote is valid.

    In software mode: verifies the self-signed measurement document.
    In hardware mode: validates CBOR/COSE Nitro attestation.
    """

    def __init__(self, expected_measurement: str, mode: Optional[str] = None):
        self.expected_measurement = expected_measurement
        self.mode = mode or _ENCLAVE_MODE

    def negotiate_key_release(self, quote_bytes: bytes) -> bytes:
        """
        Validates the attestation quote and releases the private key.
        """
        if self.mode == "software":
            return self._software_key_release(quote_bytes)
        return self._hardware_key_release(quote_bytes)

    def _software_key_release(self, quote_bytes: bytes) -> bytes:
        """
        Software mode: parse the self-signed JSON attestation document,
        verify the measurement matches, and release the key.
        """
        logger.info("Software KMS: verifying attestation document...")

        try:
            doc = json.loads(quote_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Invalid attestation document: {exc}")

        pcr0 = doc.get("pcr0", "")

        if pcr0 != self.expected_measurement:
            raise ValueError(
                f"PCR0 mismatch! Expected: {self.expected_measurement[:32]}..., "
                f"Got: {pcr0[:32]}..."
            )

        logger.info("Software KMS: measurement verified. Releasing governance key.")
        return self._read_key_file()

    def _hardware_key_release(self, quote_bytes: bytes) -> bytes:
        """
        Hardware mode: parse CBOR/COSE Nitro attestation.
        """
        try:
            import cbor2
        except ImportError:
            raise RuntimeError("cbor2 library is required for hardware KMS mode.")

        logger.info("Hardware KMS: verifying Nitro attestation...")

        try:
            cose_sign1 = cbor2.loads(quote_bytes)
            if not isinstance(cose_sign1, list) or len(cose_sign1) != 4:
                raise ValueError("Invalid COSE_Sign1 structure")

            _, _, cbor_payload, signature = cose_sign1
            doc = cbor2.loads(cbor_payload)

            pcrs = doc.get("pcrs", {})
            pcr0 = pcrs.get(0)

            if not pcr0:
                raise ValueError("Attestation document missing PCR0.")

            pcr0_hex = pcr0.hex()
            if pcr0_hex != self.expected_measurement:
                raise ValueError(
                    f"PCR0 mismatch! Expected: {self.expected_measurement}, "
                    f"Got: {pcr0_hex}"
                )

            logger.info("Hardware KMS: attestation verified. Releasing governance key.")
            return self._read_key_file()

        except Exception as exc:
            logger.error("KMS attestation verification failed: %s", exc)
            raise RuntimeError(f"KMS: attestation failed. Key release denied. Error: {exc}")

    def _read_key_file(self) -> bytes:
        """Read the governance private key from the configured path."""
        from config import settings
        key_path = settings.PRIVATE_KEY_PATH

        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Governance key not found at: {key_path}")

        with open(key_path, "rb") as f:
            return f.read()


def fetch_keys_via_attestation(enclave_id: str, expected_measurement: str) -> bytes:
    """
    Helper function to be called from the runtime to fetch keys.
    """
    from .attestation import TEEAttestation

    attester = TEEAttestation(enclave_id=enclave_id)
    quote_bytes = attester.generate_quote(user_data="nonce_for_kms")

    kms = RemoteKMS(expected_measurement=expected_measurement)
    return kms.negotiate_key_release(quote_bytes)
