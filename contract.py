import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ContractVersion:
    protocol_version: str = "3.1"
    contract_schema: str = "cgi-attestation-v3.1"
    assurance_level: str = "A5"

@dataclass
class ExecutionClaims:
    model_identity: str = "sha256:qwen_0_5b"
    execution_mode: str = "deterministic"
    network_policy: str = "deny-all"
    tool_policy: str = "no-external-tools"
    provenance: str = "complete"
    policy_hash: str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

@dataclass
class ValidityRules:
    max_clock_skew_ms: int = 5000
    expires_after_timestamp: int | None = None

@dataclass
class TrustAssumptions:
    requires_secure_tee: bool = True
    requires_hash_collision_resistance: str = "SHA-256"
    requires_audit_trail: bool = True
    # Legacy blockchain fields (kept for backward compat, default False)
    requires_groth16_soundness: bool = False
    requires_bn128_security: bool = False

@dataclass
class ContractParameters:
    model_id: str
    max_output_tokens: int
    temperature: float
    seed: int
    required_data_sources: list[str] = field(default_factory=list)
    # Audit & Security fields
    data_classification: str = "PUBLIC"     # CONFIDENTIAL | PII | PUBLIC
    purpose_of_use: str = "GENERAL"       # GENERAL | OPERATIONS | RESEARCH
    authorized_by: str = ""                 # API key ID or user identifier

    def __post_init__(self):
        if not isinstance(self.max_output_tokens, int):
            raise TypeError(f"max_output_tokens must be int, got {type(self.max_output_tokens)}")
        if not isinstance(self.temperature, (int, float)):
            raise TypeError(f"temperature must be float, got {type(self.temperature)}")
        if not isinstance(self.seed, int):
            raise TypeError(f"seed must be int, got {type(self.seed)}")
        if self.data_classification not in ("CONFIDENTIAL", "PII", "PUBLIC"):
            raise ValueError(f"data_classification must be CONFIDENTIAL, PII, or PUBLIC, got {self.data_classification}")

@dataclass
class RequiredObligations:
    zk_proof_required: bool = False
    watermark_type: str | None = None

@dataclass
class SemanticBounds:
    allowed_intents: list[str] = field(default_factory=lambda: ["*"])
    max_transaction_value: float = 0.0
    schema_strict_mode: bool = True

class InferenceContract:
    """
    The Universal Standard Inference Contract v3.
    Separates assertions (Claims) from parameters and validation rules.
    """
    def __init__(self, 
                 execution_id: str,
                 prompt_hash: str,
                 version: ContractVersion,
                 parameters: ContractParameters,
                 claims: ExecutionClaims,
                 validity: ValidityRules,
                 trust_assumptions: TrustAssumptions,
                 semantic_bounds: SemanticBounds | None = None,
                 obligations: RequiredObligations | None = None,
                 extensions: dict[str, Any] | None = None):
        self.execution_id = execution_id
        self.prompt_hash = prompt_hash
        self.version = version
        self.parameters = parameters
        self.claims = claims
        self.validity = validity
        self.trust_assumptions = trust_assumptions
        self.semantic_bounds = semantic_bounds or SemanticBounds()
        self.obligations = obligations or RequiredObligations()
        self.extensions = extensions or {}
        self.validate()

    def validate(self):
        if not self.execution_id.startswith("exec-"):
            raise ValueError("execution_id must start with 'exec-'")
        if not self.prompt_hash:
            raise ValueError("prompt_hash cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "prompt_hash": self.prompt_hash,
            "version": asdict(self.version),
            "parameters": asdict(self.parameters),
            "claims": asdict(self.claims),
            "validity": asdict(self.validity),
            "trust_assumptions": asdict(self.trust_assumptions),
            "semantic_bounds": asdict(self.semantic_bounds),
            "obligations": asdict(self.obligations),
            "extensions": self.extensions
        }

    def serialize(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def compute_contract_hash(self) -> str:
        return hashlib.sha256(self.serialize().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'InferenceContract':
        return cls(
            execution_id=data["execution_id"],
            prompt_hash=data["prompt_hash"],
            version=ContractVersion(**data["version"]),
            parameters=ContractParameters(**data["parameters"]),
            claims=ExecutionClaims(**data["claims"]),
            validity=ValidityRules(**data["validity"]),
            trust_assumptions=TrustAssumptions(**data.get("trust_assumptions", {})),
            semantic_bounds=SemanticBounds(**data.get("semantic_bounds", {})),
            obligations=RequiredObligations(**data.get("obligations", {})),
            extensions=data.get("extensions", {})
        )
