from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = "development"
    app_name: str = "previo-pls-security"
    app_version: str = "1.0.0"

    database_url: str = "postgresql+psycopg://previopls:previopls@localhost:5432/previopls"

    jwt_private_key_path: Path = Path("./keys/jwt_private.pem")
    jwt_public_key_path: Path = Path("./keys/jwt_public.pem")
    jwt_issuer: str = "previo-pls"
    jwt_audience: str = "previo-pls-clients"
    jwt_access_ttl_minutes: int = 15
    jwt_refresh_ttl_days: int = 7

    fernet_key: str = Field(..., min_length=32)
    cpf_hash_pepper: str = Field(..., min_length=16)
    hmac_payload_secret: str = Field(..., min_length=16)

    cors_origins: str = ""
    rate_limit_global: str = "100/minute"
    rate_limit_login: str = "5/minute"
    rate_limit_llm: str = "10/minute"

    lockout_max_failures: int = 5
    lockout_window_seconds: int = 60
    lockout_duration_seconds: int = 900

    retention_years: int = 5

    security_alert_webhook_url: str = ""

    @field_validator("cors_origins")
    @classmethod
    def _validate_origins(cls, v: str) -> str:
        return v.strip()

    @property
    def cors_origin_list(self) -> List[str]:
        if not self.cors_origins:
            return []
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_prod(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
