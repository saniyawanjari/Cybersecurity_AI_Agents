"""Configuration settings loaded from environment variables and .env file."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings using Pydantic Settings."""

    DATABASE_URL: str = "sqlite:///./audit.db"
    OPA_URL: str = "http://localhost:8181/v1/data/authz/allow"
    ADMIN_KEY: str = "supersecretadminkey123"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
