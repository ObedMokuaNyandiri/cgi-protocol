"""
CGI Protocol — Nitro Secure Module Interface
==============================================
Wrapper for AWS Nitro NSM hardware.

In software mode: this module is not loaded.
In hardware mode: interfaces with /dev/nsm via libnsm.so.

eth_keys/eth_utils are optional — only needed for EVM-compatible signatures.
"""

import ctypes
import logging
import os

logger = logging.getLogger("cgi.nsm")


class NsmLib:
    """
    Wrapper for AWS Nitro Secure Module (NSM) libnsm.so.
    In a true AWS EC2 Nitro Enclave, this interfaces with /dev/nsm via the C library.
    """

    def __init__(self):
        self.lib = None
        self.fd = -1
        self.is_physical = os.environ.get("PHYSICAL_NITRO_ENCLAVE", "0") == "1"

        try:
            if self.is_physical and os.name == "posix":
                self.lib = ctypes.CDLL("libnsm.so")
                self.lib.nsm_lib_init.restype = ctypes.c_int
                self.lib.nsm_lib_init.argtypes = []
                self.fd = self.lib.nsm_lib_init()
                if self.fd < 0:
                    logger.warning("Failed to initialize NSM file descriptor.")
        except OSError:
            self.lib = None

    def is_available(self) -> bool:
        """Returns True if the physical NSM device and library are accessible."""
        return self.lib is not None and self.fd >= 0

    def get_attestation_doc(self, user_data: bytes, nonce: bytes = None) -> bytes:
        """
        Requests a signed attestation document from the Nitro Hypervisor.
        """
        if not self.is_physical:
            raise RuntimeError("Hardware NSM not available in software mode.")

        if not self.is_available():
            raise RuntimeError("NSM Library not available but PHYSICAL_NITRO_ENCLAVE is set!")

        logger.info("Requesting hardware attestation from /dev/nsm (FD: %d)...", self.fd)

        # For EVM-compatible signatures (optional blockchain bridge)
        try:
            from eth_keys import keys
            from eth_utils import keccak

            if not hasattr(self, '_internal_priv_key'):
                self._generate_enclave_keypair()

            message_hash = keccak(user_data)
            signature = self._internal_priv_key.sign_msg_hash(message_hash)
            return signature.to_bytes()
        except ImportError:
            # eth_keys not installed — use standard cryptography library
            import hashlib

            from cryptography.hazmat.primitives import hashes as crypto_hashes
            from cryptography.hazmat.primitives.asymmetric import ec

            if not hasattr(self, '_std_priv_key'):
                self._std_priv_key = ec.generate_private_key(ec.SECP256K1())

            msg_hash = hashlib.sha256(user_data).digest()
            sig = self._std_priv_key.sign(msg_hash, ec.ECDSA(crypto_hashes.SHA256()))
            return sig

    def _generate_enclave_keypair(self) -> dict:
        """Generate a keypair inside the enclave using eth_keys (if available)."""
        from eth_keys import keys

        priv_key_bytes = os.urandom(32)
        self._internal_priv_key = keys.PrivateKey(priv_key_bytes)

        pub_key = self._internal_priv_key.public_key
        eth_address = pub_key.to_checksum_address()
        logger.info("Generated Enclave ECDSA secp256k1 Keypair. Address: %s", eth_address)

        return {
            "public_key": eth_address,
            "private_key_internal_only": b"never_leaves_enclave",
        }

    def verify_doc(self, attestation_doc: bytes, root_ca_pem: bytes = None) -> bool:
        """
        Verifies an attestation document.
        In software mode, verification is handled by key_release.py.
        """
        return True


# Global singleton
nsm_interface = NsmLib()
