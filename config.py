"""
CGI Protocol — Centralized Configuration
==========================================
Single source of truth for all runtime configuration.
Loads from environment variables and/or a .env file.

Usage:
    from config import settings
    print(settings.API_PORT)
"""

from __future__ import annotations

import os
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    All CGI Protocol configuration.
    Every value can be overridden via environment variable (prefix-free).
    """

    # ── Paths ─────────────────────────────────────────────────────
    BASE_DIR: str = Field(
        default_factory=lambda: os.path.dirname(os.path.abspath(__file__))
    )

    @property
    def AUTH_DIR(self) -> str:
        return os.path.join(self.BASE_DIR, "auth")

    @property
    def OUTPUT_DIR(self) -> str:
        return os.path.join(self.BASE_DIR, "outputs")

    @property
    def LOG_DIR(self) -> str:
        return os.path.join(self.BASE_DIR, "logs")

    @property
    def AUDIT_FILE(self) -> str:
        return os.path.join(self.LOG_DIR, "audit.jsonl")

    @property
    def REPLAY_FILE(self) -> str:
        return os.path.join(self.LOG_DIR, "replay_cache.json")

    @property
    def LATEST_BUNDLE(self) -> str:
        return os.path.join(self.OUTPUT_DIR, "portable_attestation_latest.json")

    @property
    def CHAIN_FILE(self) -> str:
        return os.path.join(self.OUTPUT_DIR, "chain.jsonl")

    @property
    def DB_PATH(self) -> str:
        return os.path.join(self.BASE_DIR, "data", "audit_ledger.db")

    @property
    def PRIVATE_KEY_PATH(self) -> str:
        return os.path.join(self.AUTH_DIR, "private_key.pem")

    # ── API Server ────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 1  # SQLite + subprocess = single worker only
    API_TITLE: str = "CGI Protocol — Universal Verifiable AI"
    API_VERSION: str = "2.1.0"
    DOMAIN_CONTEXT: str = "GENERAL"  # MEDICAL | LEGAL | FINANCIAL | GOVERNMENT | MEDIA | GENERAL

    # ── Licensing ────────────────────────────────────────────
    # ENFORCE  = hard fail if license missing/invalid (production default)
    # WARN     = log warning but start anyway (development only)
    # DISABLED = skip all license checks (open source / self-hosted)
    LICENSE_ENFORCEMENT: str = "ENFORCE"    # Use DISABLED for open-source deployments
    LICENSE_KEY_PATH: str = ""               # Path to the client's license_*.json file
    ISSUER_PUBLIC_KEY_PATH: str = ""         # Path to issuer_public.pem (embedded in your Docker image)

    @property
    def ISSUER_PUB_KEY_PATH(self) -> str:
        """Resolve issuer public key path: explicit setting, or auto-detect from auth dir."""
        if self.ISSUER_PUBLIC_KEY_PATH:
            return self.ISSUER_PUBLIC_KEY_PATH
        auto = os.path.join(self.AUTH_DIR, "issuer_public.pem")
        return auto if os.path.exists(auto) else ""

    # ── Security ──────────────────────────────────────────────────
    API_KEYS_FILE: str = ""  # Path to JSON file with API keys; empty = no auth
    RATE_LIMIT_RPM: int = 30  # Requests per minute per API key (overridden by license tier)
    # SECURITY: CORS_ORIGINS must be explicitly configured in production.
    # An empty list means no cross-origin requests are allowed (secure default).
    # For local dev only, set CORS_ORIGINS=["http://localhost:3000"] in .env
    CORS_ORIGINS: list[str] = Field(default_factory=list)  # Secure default: deny all cross-origin
    MAX_PROMPT_LENGTH: int = 4096  # Characters (overridden by license tier)

    # ── Worker / Inference ────────────────────────────────────
    # Supported backends (set AI_BACKEND_TYPE to one of these):
    #   Cloud:  gemini_native | openai_compatible | anthropic | azure_openai |
    #           groq | mistral | together_ai | huggingface_api | bedrock | cohere
    #   Local:  ollama_local | vllm_local | llamacpp_server | huggingface_local
    AI_BACKEND_TYPE: str = "gemini_native"

    # Generic endpoint + key (used by openai_compatible, ollama, vllm, llamacpp)
    AI_ENDPOINT_URL: str = ""
    # SECURITY: Never commit a real API key here. Set AI_API_KEY in your .env file or
    # environment variables. An empty default forces explicit operator configuration.
    AI_API_KEY: str = ""

    # Optional system prompt injected by all adapters that support it.
    # Overrides the adapter's built-in default system instruction.
    AI_SYSTEM_PROMPT: str = ""

    # ── Azure OpenAI ──────────────────────────────────────
    # Required when AI_BACKEND_TYPE=azure_openai
    AZURE_OPENAI_RESOURCE: str = ""   # e.g. my-company-openai
    AZURE_OPENAI_DEPLOYMENT: str = "" # e.g. gpt-4o-deployment
    AZURE_API_VERSION: str = "2024-02-01"

    # ── AWS Bedrock ──────────────────────────────────────
    # Reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
    # from the environment (standard AWS SDK convention).
    # No extra settings needed here — boto3 handles credential resolution.

    MODEL_PATH: str = ""
    MODEL_ID: str = "gemini-2.5-flash"
    # ALLOWED_MODELS is a whitelist for TRIAL/STARTER/PROFESSIONAL license tiers.
    # ENTERPRISE and LICENSE_ENFORCEMENT=DISABLED skip this check entirely.
    # For local backends (ollama, vllm, llamacpp), set to [] to allow any model.
    ALLOWED_MODELS: list[str] = Field(default_factory=lambda: [
        # Google Gemini
        "gemini-2.5-flash", "gemini-2.5-pro", "gemini-1.5-pro-latest",
        "gemini-1.5-flash-latest", "gemini-2.0-flash-exp",
        # OpenAI
        "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo",
        # Anthropic
        "claude-opus-4-5", "claude-sonnet-4-5", "claude-haiku-3-5",
        "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
        # Groq
        "llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768",
        # Mistral
        "mistral-large-latest", "mistral-small-latest", "codestral-latest",
        # Together AI
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
        # Local models (generic IDs used by ollama/vllm)
        "qwen_0_5b", "llama3.2", "llama3.1", "mistral", "phi3", "gemma2",
        "deepseek-r1", "qwen2.5",
    ])
    WORKER_TIMEOUT_SECONDS: int = 600  # Kill worker after this
    DEFAULT_MAX_TOKENS: int = 200
    DEFAULT_SEED: int = 42
    DEFAULT_TEMPERATURE: float = 0.8

    # ── Audit & Security ──────────────────────────────────────────
    # Supported: PUBLIC | CONFIDENTIAL | PII | PRIVILEGED | CLASSIFIED
    DEFAULT_DATA_CLASSIFICATION: str = "PUBLIC"
    AUDIT_RETENTION_DAYS: int = 2190  # 6 years default retention
    ENABLE_SENSITIVE_ENCRYPTION: bool = False  # Enable AES-256-GCM for sensitive fields
    SENSITIVE_ENCRYPTION_KEY: str = ""  # 32-byte hex key for sensitive data encryption

    # ── Blockchain Anchoring Engine ───────────────────────────────
    ANCHOR_ENABLED: bool = True  # Set False to disable anchoring entirely
    ANCHOR_INTERVAL_SECONDS: int = 3600  # How often to run anchor cycle (default: 1 hour)
    ANCHOR_MIN_BATCH_SIZE: int = 1   # Anchor even 1 record (set higher in high-volume prod)
    # OTS Calendar servers (public, free, maintained by Bitcoin Core contributors)
    OTS_CALENDAR_URLS: list[str] = Field(default_factory=lambda: [
        "https://alice.btc.calendar.opentimestamps.org",
        "https://bob.btc.calendar.opentimestamps.org",
        "https://finney.calendar.eternitywall.com",
    ])



    @property
    def ANCHOR_DIR(self) -> str:
        return os.path.join(self.OUTPUT_DIR, "anchor_proofs")

    # ── Enclave / Attestation ─────────────────────────────────────
    ENCLAVE_MODE: str = "software"  # "software" | "nitro"
    ENCLAVE_ID: str = "cgi-software-enclave-1"

    # ── Logging ───────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # "json" | "text"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached singleton — call this from all modules."""
    return Settings()


# Module-level convenience alias
settings = get_settings()
