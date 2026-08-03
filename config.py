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
from typing import List, Optional

from pydantic_settings import BaseSettings
from pydantic import Field


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
    API_TITLE: str = "CGI Protocol — Healthcare Verifiable AI"
    API_VERSION: str = "2.0.0"

    # ── Security ──────────────────────────────────────────────────
    API_KEYS_FILE: str = ""  # Path to JSON file with API keys; empty = no auth
    RATE_LIMIT_RPM: int = 30  # Requests per minute per API key
    CORS_ORIGINS: List[str] = Field(default_factory=lambda: ["*"])
    MAX_PROMPT_LENGTH: int = 4096  # Characters

    # ── Worker / Inference ────────────────────────────────────────
    MODEL_PATH: str = "./models/models/qwen_0_5b"
    MODEL_ID: str = "qwen_0_5b"
    ALLOWED_MODELS: List[str] = Field(default_factory=lambda: ["qwen_0_5b"])
    WORKER_TIMEOUT_SECONDS: int = 600  # Kill worker after this
    DEFAULT_MAX_TOKENS: int = 200
    DEFAULT_SEED: int = 42
    DEFAULT_TEMPERATURE: float = 0.8

    # ── Healthcare / HIPAA ────────────────────────────────────────
    DEFAULT_DATA_CLASSIFICATION: str = "PUBLIC"  # PHI | PII | PUBLIC
    AUDIT_RETENTION_DAYS: int = 2190  # 6 years for HIPAA
    ENABLE_PHI_ENCRYPTION: bool = False  # Enable AES-256-GCM for PHI fields
    PHI_ENCRYPTION_KEY: str = ""  # 32-byte hex key for PHI encryption

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
