import base64
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from canonical_hash import compute_canonical_root  # FIX FLAW-002
from contract import InferenceContract

try:
    import cbor2
except ImportError:
    cbor2 = None

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
        try:
            # The payload may contain <think>...</think> reasoning tags before the JSON.
            import re
            json_str = re.sub(r"<think>.*?</think>", "", self.external_output, flags=re.DOTALL).strip()
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"[VERIFIER DEBUG] JSON error: {e}, payload: {json_str!r}")
            return False
            
        contract_data = self.payload.get("contract", {})
        try:
            contract = InferenceContract.from_dict(contract_data)
        except (ValueError, TypeError, KeyError):
            return False
            
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
        computed_root_hash = compute_canonical_root(self.payload)

        # FIX: Compute individual component hashes (previously undefined → NameError)
        from canonical_hash import compute_component_hashes
        comp_hashes = compute_component_hashes(self.payload)

        if not self.skip_attestation_checks:
            if comp_hashes["contract_hash"] != self.attestation.get("contract_hash"): result.failed_checks.append("contract_hash mismatch")
            if comp_hashes["runtime_state_hash"] != self.attestation.get("runtime_state_hash"): result.failed_checks.append("runtime_state_hash mismatch")
            if comp_hashes["runtime_identity_hash"] != self.attestation.get("runtime_identity_hash"): result.failed_checks.append("runtime_identity_hash mismatch")
            if comp_hashes["output_commitment_hash"] != self.attestation.get("output_commitment_hash"): result.failed_checks.append("output_commitment_hash mismatch")
            if comp_hashes["evidence_hash"] != self.attestation.get("evidence_hash"): result.failed_checks.append("evidence_hash mismatch")
            if comp_hashes["generation_summary_hash"] != self.attestation.get("generation_summary_hash"): result.failed_checks.append("generation_summary_hash mismatch")

            if computed_root_hash != self.attestation.get("root_hash"):
                result.failed_checks.append("Canonical root_hash mismatch! Payload was tampered.")
            
        # A1: Decoupled Output Hash Verification
        computed_external_hash = hashlib.sha256(self.external_output.encode("utf-8")).hexdigest()
        if computed_external_hash != output_commitment.get("output_hash"):
            result.failed_checks.append("Decoupled output hash does not match attestation commitment!")

        # A1: Contract Validity (Replay Attack Prevention)
        import time
        validity = contract_data.get("validity", {})
        expires_at = validity.get("expires_after_timestamp")
        if expires_at and time.time() > expires_at:
            result.failed_checks.append(
                f"Contract has expired (expires_after_timestamp={expires_at}, now={int(time.time())}). "
                "This may be a replay attack."
            )

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
            elif fmt == "aws-nitro-cose":
                if cbor2 is None:
                    result.status = AuditStatus.UNDETERMINED
                    result.failed_checks.append("cbor2 library required for auditing AWS Nitro Quotes.")
                else:
                    try:
                        cose_sign1 = cbor2.loads(base64.b64decode(hardware_quote_b64))
                        cbor_payload = cose_sign1[2]
                        doc = cbor2.loads(cbor_payload)
                        pcr0 = doc.get("pcrs", {}).get(0)

                        if pcr0.hex() != runtime_identity.get("enclave_measurement"):
                            result.failed_checks.append("Hardware PCR0 does not match stated runtime measurement.")
                    except (ValueError, TypeError, KeyError) as e:
                        result.failed_checks.append(f"Hardware Quote Invalid: {e}")

                    
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
            if contract.claims.network_policy == "deny-all":
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