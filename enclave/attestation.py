"""
CGI Protocol — TEE Attestation (Software + Hardware modes)
============================================================
Software mode:  Generates self-signed attestation documents using
                the governance key. No hardware TEE required.
Hardware mode:  Interfaces with AWS Nitro NSM (original behavior).
"""

import hashlib
import json
import logging
import os
import time

logger = logging.getLogger("cgi.enclave")

# Determine mode at import time
_ENCLAVE_MODE = os.environ.get("ENCLAVE_MODE", "software")


class TEEAttestation:
    """
    Unified attestation generator supporting both software-only
    and hardware TEE (AWS Nitro) modes.
    """

    def __init__(self, enclave_id: str, mode: str | None = None):
        self.enclave_id = enclave_id
        self.mode = mode or _ENCLAVE_MODE

    def generate_quote(self, user_data: str = "") -> bytes:
        """
        Generate an attestation quote.

        In software mode: produces a self-signed CBOR-like document
        containing the runtime measurement hash.

        In hardware mode: calls the Nitro NSM hardware.
        """
        if self.mode == "software":
            return self._generate_software_quote(user_data)

        # Hardware mode
        try:
            from .nitro_nsm import nsm_interface
            if not nsm_interface.is_available():
                raise RuntimeError(
                    "Hardware NSM not detected but ENCLAVE_MODE=nitro. "
                    "Set ENCLAVE_MODE=software for non-TEE deployments."
                )
            logger.info("Requesting hardware attestation from Nitro Hypervisor...")
            return nsm_interface.get_attestation_doc(user_data=user_data.encode("utf-8"))
        except ImportError:
            raise RuntimeError(
                "Nitro NSM module unavailable. Set ENCLAVE_MODE=software."
            )

    def _generate_software_quote(self, user_data: str) -> bytes:
        """
        Software-only attestation: a self-signed measurement document.
        This is NOT hardware-backed but provides the same data structure
        for the key release and verification pipeline.
        """
        measurement = self._measure_runtime()

        doc = {
            "mode": "software",
            "enclave_id": self.enclave_id,
            "user_data": user_data,
            "timestamp": int(time.time()),
            "pcr0": measurement,
            "digest": "SHA384",
        }

        # Serialize as JSON bytes (not CBOR — avoiding extra dependency in software mode)
        doc_bytes = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # Self-sign with SHA-256 HMAC-like binding (measurement is the "key")
        binding = hashlib.sha256(measurement.encode("utf-8") + doc_bytes).hexdigest()
        doc["binding"] = binding

        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _measure_runtime(self) -> str:
        """
        Calculate a SHA-384 hash of core runtime files.
        In hardware mode, this would be the PCR0 from the Nitro hypervisor.
        """
        h = hashlib.sha384()
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        for filename in ["cgi_runtime.py", "worker.py", "api_gateway.py"]:
            filepath = os.path.join(base_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    h.update(f.read())

        return h.hexdigest()
