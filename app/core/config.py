import os
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # PREVIOPLS_ENV_FILE="" desliga o .env (os testes nao podem herdar o segredo local)
        env_file=os.environ.get("PREVIOPLS_ENV_FILE", ".env") or None,
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
    # chave publica anterior, aceita so durante a rotacao (kid diferente)
    jwt_previous_public_key_path: Path | None = None
    jwt_issuer: str = "previo-pls"
    jwt_audience: str = "previo-pls-clients"
    jwt_access_ttl_minutes: int = 15
    jwt_refresh_ttl_days: int = 7

    # FERNET_KEYS="nova,antiga": a primeira cifra, todas decifram (rotacao sem downtime).
    # FERNET_KEY sozinha continua valendo pra quem ainda nao migrou o .env
    fernet_keys: str = ""
    fernet_key: str = ""
    cpf_hash_pepper: str = Field(..., min_length=16)
    hmac_payload_secret: str = Field(..., min_length=16)

    cors_origins: str = ""
    rate_limit_global: str = "100/minute"
    rate_limit_login: str = "5/minute"
    rate_limit_llm: str = "10/minute"
    # memory:// serve pra uma replica; com mais de uma, redis://host:6379
    rate_limit_storage_uri: str = "memory://"

    lockout_max_failures: int = 5
    lockout_window_seconds: int = 60
    lockout_duration_seconds: int = 900

    mass_query_threshold: int = 50

    retention_years: int = 5
    telemetria_retention_days: int = 90

    security_alert_webhook_url: str = ""

    metrics_token: str = ""
    # alem do stdout, o JSON de log vai pra este arquivo (o promtail le dele, sem docker.sock)
    log_file: str = ""

    # usuarios de demo: so fora de producao; as senhas vem do .env, nunca do codigo
    seed_default_users: bool | None = None
    seed_admin_password: str = ""
    seed_consultor_password: str = ""
    seed_analista_password: str = ""

    # primeiro admin de producao (criado no boot se nao existir)
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    bootstrap_admin_name: str = "Administrador"

    @field_validator("cors_origins")
    @classmethod
    def _validate_origins(cls, v: str) -> str:
        return v.strip()

    @property
    def fernet_key_list(self) -> List[str]:
        keys = [k.strip() for k in self.fernet_keys.split(",") if k.strip()]
        if not keys and self.fernet_key:
            keys = [self.fernet_key.strip()]
        return keys

    @model_validator(mode="after")
    def _segredos(self) -> "Settings":
        if not self.fernet_key_list:
            raise ValueError("FERNET_KEYS (ou FERNET_KEY) obrigatoria")
        if not self.is_prod:
            return self
        # em producao o boot falha com segredo de exemplo, curto ou reaproveitado
        fracos = ("troque", "change", "exemplo", "example", "dev", "teste", "test")
        segredos = {"CPF_HASH_PEPPER": self.cpf_hash_pepper, "HMAC_PAYLOAD_SECRET": self.hmac_payload_secret}
        for nome, valor in segredos.items():
            if len(valor) < 32 or any(f in valor.lower() for f in fracos):
                raise ValueError(f"{nome} fraco ou de exemplo em producao")
        if self.cpf_hash_pepper == self.hmac_payload_secret:
            raise ValueError("CPF_HASH_PEPPER e HMAC_PAYLOAD_SECRET precisam ser diferentes")
        if not self.cors_origin_list or "*" in self.cors_origin_list:
            raise ValueError("CORS_ORIGINS precisa de whitelist explicita em producao")
        return self

    @property
    def cors_origin_list(self) -> List[str]:
        if not self.cors_origins:
            return []
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_prod(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def should_seed_default_users(self) -> bool:
        if self.seed_default_users is None:
            return not self.is_prod
        return self.seed_default_users and not self.is_prod


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
