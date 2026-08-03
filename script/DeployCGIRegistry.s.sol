// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../contracts/CGIRegistry.sol";
import "../contracts/ICGIVerifier.sol";

/**
 * @title DummyVerifier
 * @dev Deployed dynamically during setup if a hardcoded EZKL Verifier is not provided.
 * It always returns `true` for testing purposes. MUST be replaced in production.
 */
contract DummyVerifier is ICGIVerifier {
    function verifyProof(
        bytes memory proof,
        uint256[] memory pubSignals
    ) external pure override returns (bool) {
        // Suppress unused variable warnings
        proof;
        pubSignals;
        return true;
    }
}

contract DeployCGIRegistry is Script {
    function run() external {
        // Read deployer private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        // Optionally read the ultimate DAO/Timelock owner
        address finalOwner = vm.envOr("DAO_TIMELOCK_ADDRESS", address(0));

        // Start broadcasting transactions to the RPC network
        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy the Verifier (or use existing)
        address verifierAddress = vm.envOr("EZKL_VERIFIER_ADDRESS", address(0));
        if (verifierAddress == address(0)) {
            console.log("No EZKL_VERIFIER_ADDRESS provided. Deploying DummyVerifier (Dev Mode)...");
            DummyVerifier dummy = new DummyVerifier();
            verifierAddress = address(dummy);
        }

        // 2. Deploy the core CGIRegistry
        console.log("Deploying CGIRegistry pointing to Verifier at:", verifierAddress);
        CGIRegistry registry = new CGIRegistry(verifierAddress);

        // 3. Transfer Ownership to DAO / Timelock to prevent Rug Pulls
        if (finalOwner != address(0) && finalOwner != registry.owner()) {
            console.log("Transferring Ownership to Timelock/DAO at:", finalOwner);
            registry.transferOwnership(finalOwner);
        } else {
            console.log("[WARNING] Ownership retained by the deployer wallet! Ensure this is intended for local dev.");
        }

        vm.stopBroadcast();
        
        console.log("CGIRegistry successfully deployed at:", address(registry));
    }
}
