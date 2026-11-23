"""Typed runtime configuration loaded from environment / .env."""

from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings for producer, middleware, OPA, Ollama, and SQLite."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    kafka_bootstrap_servers: str = Field(
        default="localhost:9092",
        alias="KAFKA_BOOTSTRAP_SERVERS",
    )
    kafka_audit_topic: str = Field(
        default="audit-events",
        alias="KAFKA_AUDIT_TOPIC",
    )
    kafka_consumer_group: str = Field(
        default="audit-middleware-mvp",
        alias="KAFKA_CONSUMER_GROUP",
    )
    kafka_auto_offset_reset: str = Field(
        default="earliest",
        alias="KAFKA_AUTO_OFFSET_RESET",
    )

    opa_url: str = Field(
        default="http://localhost:8181",
        alias="OPA_URL",
    )
    opa_deny_paths: List[str] = Field(
        default_factory=lambda: [
            "/v1/data/aws/s3/compliance/deny",
            "/v1/data/aws/iam_kms/compliance/deny",
        ],
        alias="OPA_DENY_PATHS",
    )

    ollama_base_url: str = Field(
        default="http://localhost:11434",
        alias="OLLAMA_BASE_URL",
    )
    ollama_model: str = Field(
        default="llama3.2",
        alias="OLLAMA_MODEL",
    )
    ollama_timeout_seconds: float = Field(
        default=30.0,
        alias="OLLAMA_TIMEOUT_SECONDS",
    )
    llm_window_size: int = Field(
        default=5,
        alias="LLM_WINDOW_SIZE",
    )

    sqlite_db_path: str = Field(
        default="./data/audit_mvp.db",
        alias="SQLITE_DB_PATH",
    )
    producer_interval_seconds: float = Field(
        default=2.0,
        alias="PRODUCER_INTERVAL_SECONDS",
    )

    @field_validator("opa_deny_paths", mode="before")
    @classmethod
    def _split_deny_paths(cls, value: object) -> object:
        if isinstance(value, str):
            parts = [part.strip() for part in value.split(",")]
            return [part for part in parts if part]
        return value


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
