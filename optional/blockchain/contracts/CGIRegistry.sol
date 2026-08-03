// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ICGIVerifier.sol";

/**
 * @title CGIRegistry
 * @dev The primary on-chain state transition engine for the CGI Protocol.
 * Enforces ZK-SNARK mathematically proven state updates (Optimistic Commit).
 * Actual trade execution is delegated to off-chain keepers listening to the `StateTransition` event.
 */
contract CGIRegistry {
    
    ICGIVerifier public immutable verifier;
    
    // The canonical current state root (Merkle Root of the AI's memory tree)
    uint256 public currentStateRoot;
    
    // Governance / Operator authority
    address public owner;
    
    // Prevent replay attacks (hash of token/attestation => bool)
    mapping(bytes32 => bool) public executedAttestations;

    event StateTransition(
        uint256 indexed previousRoot,
        uint256 indexed newRoot,
        uint256 outputHash,
        bytes32 attestationId
    );

    error Unauthorized();
    error InvalidProof();
    error RootMismatch(uint256 expected, uint256 provided);
    error ReplayDetected(bytes32 attestationId);

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /**
     * @param _verifier The address of the deployed EZKL/SnarkJS cryptographic verifier.
     * @param _initialStateRoot The genesis merkle root of the protocol.
     */
    constructor(address _verifier, uint256 _initialStateRoot) {
        verifier = ICGIVerifier(_verifier);
        currentStateRoot = _initialStateRoot;
        owner = msg.sender;
    }

    /**
     * @notice Submits a ZK-proven state transition to the blockchain.
     * @param proof The zero-knowledge proof bytes.
     * @param outputHash The hash of the action payload (e.g., trade intent).
     * @param newRoot The resulting merkle root after the state transition.
     * @param attestationId A unique identifier (e.g., token_id hash) to prevent replays.
     */
    function submitAttestation(
        bytes calldata proof,
        uint256 outputHash,
        uint256 newRoot,
        bytes32 attestationId
    ) external {
        // 1. Replay Protection
        if (executedAttestations[attestationId]) {
            revert ReplayDetected(attestationId);
        }

        // 2. Prepare Public Signals
        // The order MUST match the compiled Circom/Halo2 circuit definition exactly.
        // [previous_root, output_hash, new_root]
        uint256[] memory pubSignals = new uint256[](3);
        pubSignals[0] = currentStateRoot;
        pubSignals[1] = outputHash;
        pubSignals[2] = newRoot;

        // 3. Cryptographic ZK-SNARK Verification
        bool isValid = verifier.verifyProof(proof, pubSignals);
        if (!isValid) revert InvalidProof();

        // 4. Update Canonical State
        uint256 prevRoot = currentStateRoot;
        currentStateRoot = newRoot;
        executedAttestations[attestationId] = true;

        // 5. Emit Event for Off-Chain Execution (Optimistic Commit Strategy)
        // Keepers will read this event, verify the outputHash matches their local
        // decrypted action payload, and execute the trade on Uniswap/0x.
        emit StateTransition(prevRoot, newRoot, outputHash, attestationId);
    }
    
    /**
     * @notice Allows governance to update the verifier address in case of circuit upgrades.
     */
    function upgradeVerifier(address _newVerifier) external onlyOwner {
        // In a true decentralized protocol, this would be behind a Timelock controller.
        verifier = ICGIVerifier(_newVerifier);
    }
}
