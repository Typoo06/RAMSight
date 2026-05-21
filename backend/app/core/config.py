# Backend settings loaded from environment variables.

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = Field(default="development", alias="APP_ENV")
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")

    database_url: str = Field(
        default="postgresql+psycopg://memory_triage:change-me@postgres:5432/memory_triage",
        alias="DATABASE_URL",
    )
    alembic_database_url: str | None = Field(default=None, alias="ALEMBIC_DATABASE_URL")
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field(default="redis://redis:6379/0", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://redis:6379/1", alias="CELERY_RESULT_BACKEND")

    minio_endpoint: str = Field(default="minio:9000", alias="MINIO_ENDPOINT")
    minio_access_key: str = Field(default="change-me", alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field(default="change-me", alias="MINIO_SECRET_KEY")
    minio_bucket_evidence: str = Field(default="evidence", alias="MINIO_BUCKET_EVIDENCE")
    minio_bucket_reports: str = Field(default="reports", alias="MINIO_BUCKET_REPORTS")
    minio_bucket_raw_outputs: str = Field(default="raw-outputs", alias="MINIO_BUCKET_RAW_OUTPUTS")
    minio_secure: bool = Field(default=False, alias="MINIO_SECURE")
    evidence_max_upload_bytes: int = Field(default=21474836480, alias="EVIDENCE_MAX_UPLOAD_BYTES")


@lru_cache
def get_settings() -> Settings:
    return Settings()
