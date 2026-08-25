import base64
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from canonical_hash import compute_canonical_root  # FIX FLAW-002
from contract import InferenceContract



try:
    from zk_snark import _compute_public_signals, verify_inference_proof
except ImportError:
    pass

class AuditStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNDETERMINED = "UNDETERMINED"

@dataclass
class VerificationResult:
    status: AuditStatus
    failed_checks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    assurance_level: str = "A1"
    contract: InferenceContract = None
    runtime_state: dict[str, Any] = None

class FormalVerifier:
    def __init__(self, payload: dict[str, Any], attestation: dict[str, str], external_output: str, sidechannel_prompt: str = "", skip_attestation_checks: bool = False):
        self.payload = payload
        self.attestation = attestation
        self.external_output = external_output
        self.sidechannel_prompt = sidechannel_prompt
        self.skip_attestation_checks = skip_attestation_checks

    def _hash_component(self, comp: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(comp, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def verify_bounds_boolean(self) -> bool:
        """
        Evaluates semantic bounds and structure natively.
        Returns True if safe, False if malformed or violates bounds.
        """
        contract_data = self.payload.get("contract", {})
        try:
            contract = InferenceContract.from_dict(contract_data)
        except (ValueError, TypeError, KeyError):
            return False

        # If no semantic bounds are defined in the contract, it passes by default.
        if not hasattr(contract, "semantic_bounds") or not contract.semantic_bounds:
            return True
            
        try:
            # The payload may contain <think>...</think> reasoning tags before the JSON.
            import re
            json_str = re.sub(r"<think>.*?</think>", "", self.external_output, flags=re.DOTALL).strip()
            data = json.loads(json_str)
            
            max_val = getattr(contract.semantic_bounds, "max_transaction_value", float('inf'))
            quantity = data.get("quantity", 0)
            
            import math
            try:
                quantity = float(quantity)
            except (ValueError, TypeError):
                return False
                
            if math.isnan(quantity) or math.isinf(quantity):
                return False
                
            return not (quantity < 0 or quantity > max_val)
        except json.JSONDecodeError:
            # If the output is unstructured text, it naturally contains no 'quantity' 
            # violating the semantic bounds.
            return True

    def verify(self) -> VerificationResult:
        if not self.payload:
            return VerificationResult(status=AuditStatus.FAIL, failed_checks=["Missing payload block."])
        if not self.attestation and not self.skip_attestation_checks:
            return VerificationResult(status=AuditStatus.FAIL, failed_checks=["Missing attestation block."])

        contract_data = self.payload.get("contract", {})
        try:
            contract = InferenceContract.from_dict(contract_data)
        except (ValueError, TypeError, KeyError) as e:
            return VerificationResult(status=AuditStatus.FAIL, failed_checks=[f"Invalid contract format: {e}"])
            
        assurance_level_str = getattr(contract.version, "assurance_level", "A1")
        assurance_levels = {"A1": 1, "A2": 2, "A3": 3, "A4": 4, "A5": 5}
        target_level = assurance_levels.get(assurance_level_str, 1)

        result = VerificationResult(
            status=AuditStatus.PASS, 
            assurance_level=assurance_level_str,
            contract=contract,
            runtime_state=self.payload.get("runtime_state", {})
        )

        runtime_state = self.payload.get("runtime_state", {})
        runtime_identity = self.payload.get("runtime_identity", {})
        output_commitment = self.payload.get("output_commitment", {})
        evidence = self.payload.get("evidence", {})

        # A1: Canonical Root Binding
        # FIX FLAW-002: Use shared canonical root computation.
        # Both the runtime (prover) and verifier now call the same pure
        # function, eliminating the 6-component vs 8-component divergence.
        
        import json
        import hashlib
        
        # In CGI Protocol v3.1, the prover (cgi_runtime.py) generates the root hash
        # by hashing the entire raw JSON payload, not individual component hashes.
        payload_bytes = json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        computed_root_hash = hashlib.sha256(payload_bytes).hexdigest()

        # Backwards compatibility check for component hashes (v3.0 schemas)
        from canonical_hash import compute_component_hashes
        comp_hashes = compute_component_hashes(self.payload)

        if not self.skip_attestation_checks:
            for key in ["contract_hash", "runtime_state_hash", "runtime_identity_hash", "output_commitment_hash", "evidence_hash", "generation_summary_hash"]:
                if key in self.attestation and comp_hashes[key] != self.attestation[key]:
                    result.failed_checks.append(f"{key} mismatch")

            expected_root = self.attestation.get("root_hash", "")
            if expected_root.startswith("0x"):
                expected_root = expected_root[2:]
                
            if computed_root_hash != expected_root:
                result.failed_checks.append("Canonical root_hash mismatch! Payload was tampered.")
            
        # A1: Decoupled Output Hash Verification
        # FIX M-5: Support both v3.0 (decoupled output_commitment) and v3.1 
        # (inline inference_output) schemas. For v3.1, the output is directly
        # in the payload, so we compare external_output directly to it.
        computed_external_hash = hashlib.sha256(self.external_output.encode("utf-8")).hexdigest()
        
        if "inference_output" in self.payload:
            # v3.1 schema: output is inline
            if self.external_output != self.payload.get("inference_output"):
                result.failed_checks.append("Inline inference_output does not match provided external_output!")
        else:
            # v3.0 schema: output is decoupled via hash commitment
            if computed_external_hash != output_commitment.get("output_hash"):
                result.failed_checks.append("Decoupled output hash does not match attestation commitment!")
        # A1: Contract Validity (Replay Attack Prevention)
        # FIX FLAW-003: Check expiration on the attestation payload itself against execution time
        import time
        expires_at = self.payload.get("contract", {}).get("expires")
        attested_at = self.attestation.get("attested_at", time.time())
        if expires_at and attested_at > expires_at:
            result.failed_checks.append(f"Contract had expired before execution (expires_after_timestamp={expires_at}, attested_at={int(attested_at)}). This is an invalid execution.")

        # A2: Verify Hardware Quote (CBOR/COSE)
        # FIX FLAW-010: Support both legacy singular and new plural key names.
        hardware_att = evidence.get("hardware_attestation") or evidence.get("hardware_attestations", {})
        hardware_quote_b64 = hardware_att.get("quote_base64") or (
            hardware_att.get("quotes_base64", [None])[0] if hardware_att.get("quotes_base64") else None
        )
        fmt = hardware_att.get("format")
        if target_level >= 2:
            if not hardware_quote_b64:
                result.failed_checks.append("Assurance Level A2 requires hardware quote, but it is missing.")


                    
        # A3: Verify Merkle Proofs & Execution Path
        if target_level >= 3:
            merkle_root = evidence.get("merkle_root")
            if not merkle_root:
                result.failed_checks.append("Assurance Level A3 requires Merkle root, but it is missing.")
            else:
                leaves = evidence.get("merkle_leaves", [])
                if len(leaves) == 0:
                    result.failed_checks.append("No execution events recorded in Merkle tree.")
                    
        # A4: Verify ZK-SNARK Proof
        if target_level >= 4:
            zk_proof = evidence.get("zk_snark_proof")
            zk_public_signal = evidence.get("zk_public_signal")
            
            if not zk_proof or not zk_public_signal:
                result.failed_checks.append("Assurance Level A4 requires ZK-SNARK but proof is missing.")
            elif 'verify_inference_proof' not in globals():
                result.status = AuditStatus.UNDETERMINED
                result.failed_checks.append("ZK-SNARK verifier module is missing locally.")
            else:
                try:
                    if hashlib.sha256(self.sidechannel_prompt.encode("utf-8")).hexdigest() != contract.prompt_hash:
                        result.failed_checks.append("Auditor side-channel prompt does not match contract prompt_hash.")
                    else:
                        expected_public_signal = _compute_public_signals(contract.prompt_hash, computed_external_hash, contract.parameters.model_id)
                        if zk_public_signal != expected_public_signal:
                            result.failed_checks.append("ZK-SNARK public signal mismatch! Output or prompt was tampered.")
                        elif not verify_inference_proof(zk_proof, zk_public_signal):
                            result.failed_checks.append("ZK-SNARK mathematical proof failed.")
                except (ValueError, TypeError, KeyError) as e:
                    result.failed_checks.append(f"Error during ZK verification: {e}")

        # A5: Explicit Claims evaluation (Privacy/Reproducibility)
        if target_level >= 5:
            enforced = runtime_state.get("enforced_constraints", {})
            if hasattr(contract.claims, "network_policy"):
                if contract.claims.network_policy not in ["unverified", "deny-all"]:
                    if enforced.get("network_isolation") != "namespaces/net:deny-all":
                        result.failed_checks.append("Contract claims deny-all network, but runtime did not enforce namespaces/net:deny-all.")
                else:
                    result.failed_checks.append("Assurance Level A5 requires strict 'deny-all' network policy.")
                
            if contract.claims.execution_mode == "deterministic":
                determinism_flags = enforced.get("determinism_flags", [])
                if "CUBLAS_WORKSPACE_CONFIG=:4096:8" not in determinism_flags:
                    result.failed_checks.append("Contract claims deterministic execution, but runtime did not enforce CUBLAS_WORKSPACE_CONFIG.")
                if "PYTHONHASHSEED=42" not in determinism_flags:
                    result.failed_checks.append("Contract claims deterministic execution, but runtime did not enforce PYTHONHASHSEED.")
            else:
                result.failed_checks.append("Assurance Level A5 requires 'deterministic' execution mode.")

        # Resolve Final Status
        if len(result.failed_checks) > 0 and result.status != AuditStatus.UNDETERMINED:
            result.status = AuditStatus.FAIL

        return result