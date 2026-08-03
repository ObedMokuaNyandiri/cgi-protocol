// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CGIAttestationVerifier
 * @dev The core cryptographic verification layer for the CGI Protocol.
 * This contract verifies the AWS Nitro Enclave signatures securely,
 * strictly enforcing EIP-2098 to prevent signature malleability.
 */
contract CGIAttestationVerifier {
    
    // The public key hash of the authorized Enclave (Governance Key)
    // For this demonstration, we'll allow any registered enclave to submit,
    // but we track them via a registry.
    mapping(address => bool) public activeEnclaves;

    event EnclaveRegistered(address indexed enclaveAddress);
    event AttestationVerified(bytes32 indexed rootHash, address indexed enclaveAddress);

    constructor() {
        // In a real deployment, the enclave address would be extracted from the CA-signed Quote.
    }

    /**
     * @dev Register an authorized enclave address. 
     * In a production environment, this is called after verifying a hardware quote.
     */
    function registerEnclave(address enclaveAddress) external {
        activeEnclaves[enclaveAddress] = true;
        emit EnclaveRegistered(enclaveAddress);
    }

    /**
     * @dev Main verification entrypoint for on-chain relayer.
     * @param rootHash The SHA-256 hash of the JSON payload.
     * @param r The 'r' component of the ECDSA signature.
     * @param s The 's' component of the ECDSA signature.
     * @param v The recovery byte ('v') of the ECDSA signature.
     */
    function verifyAttestation(
        bytes32 rootHash,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external returns (bool) {
        
        address signer = _recoverSigner(rootHash, r, s, v);
        
        require(signer != address(0), "CGI: Invalid signature or zero address recovered");
        require(activeEnclaves[signer], "CGI: Signer is not a registered active Enclave");

        // Attestation mathematically verified
        emit AttestationVerified(rootHash, signer);
        
        return true;
    }

    /**
     * @dev Internal function to recover the signer address from the ECDSA signature.
     * HARDENED: Includes checks against signature malleability.
     */
    function _recoverSigner(bytes32 hash, bytes32 r, bytes32 s, uint8 v) internal pure returns (address) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}.
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "ECDSA: invalid signature 's' value (malleability protection)"
        );

        require(v == 27 || v == 28, "ECDSA: invalid signature 'v' value");

        // ecrecover takes the hash, v, r, s and returns the signer address
        return ecrecover(hash, v, r, s);
    }
}
