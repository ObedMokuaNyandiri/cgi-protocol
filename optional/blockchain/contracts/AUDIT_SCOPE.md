# CGI Protocol: Formal Smart Contract Audit Scope

## 1. Overview
This document strictly defines the cryptographic boundaries and invariant constraints of the CGI Protocol Smart Contracts (`CGIRegistry.sol` and `ICGIVerifier.sol`). It is intended to guide external auditing firms (e.g., Trail of Bits, ConsenSys Diligence, Zellic) during formal security reviews.

## 2. In-Scope Contracts
- `contracts/CGIRegistry.sol`
- `contracts/ICGIVerifier.sol`

*Note: The actual implementation of the EZKL ZK-SNARK verifier contract (generated dynamically via `ezkl`) is considered out of scope, as we assume the cryptographic soundness of the Halo2 plonkish arithmetization. The scope is limited strictly to how the CGI Protocol handles the verifier's `verifyProof` boolean response.*

## 3. Cryptographic Invariants to Test

Auditors are requested to aggressively test the following invariants:

### A. Strict Replay Protection
- **Invariant:** A unique `attestationId` can NEVER be submitted more than once.
- **Threat Model:** An attacker replays a valid ZK Proof to force the system to rapidly progress the state or drain funds.
- **Verification:** Ensure `usedAttestations[attestationId]` perfectly prevents duplicate execution.

### B. Cryptographic Input Binding
- **Invariant:** The `pubSignals` array must strictly follow the format: `[previousRoot, outputHash, newRoot]`.
- **Threat Model:** An attacker submits a valid proof but manipulates the array ordering to trick the registry into updating `currentStateRoot` to a malicious value.
- **Verification:** Verify that the `CGIRegistry` correctly packs these three inputs before invoking `verifier.verifyProof(proof, pubSignals)`.

### C. State Progression Integrity
- **Invariant:** A state transition can ONLY occur if `previousRoot == currentStateRoot`.
- **Threat Model:** An attacker generates a mathematically valid ZK Proof branching off an old state, causing a chain fork or overriding valid recent state.
- **Verification:** Confirm that line `require(previousRoot == currentStateRoot)` cannot be bypassed or front-run in a way that causes race conditions.

### D. Privilege Separation (Owner Roles)
- **Invariant:** The `owner` (Timelock/DAO) can ONLY update the Verifier address.
- **Threat Model:** The DAO is compromised and attempts to forge a state transition directly, bypassing the ZK circuit.
- **Verification:** Ensure there are no backdoors or `onlyOwner` modifiers on `submitAttestation`. The protocol must be purely mathematically driven.

## 4. Known Centralization Vectors
- **Upgradability:** The `updateVerifier` function allows the `owner` to change the underlying EZKL verifier contract. This is intentional to allow circuit upgrades, but it requires that the `owner` is a strictly governed Timelock/DAO. Auditors should confirm that the `owner` has no other hidden authorities.

## 5. Deployment Instructions
The system uses Foundry for deterministic deployment.
Command to deploy:
```bash
forge script script/DeployCGIRegistry.s.sol:DeployCGIRegistry --rpc-url <RPC> --broadcast
```
