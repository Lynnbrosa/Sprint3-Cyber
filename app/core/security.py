"""
Camada de autenticação e autorização.

- JWT RS256 (assimétrica) com claims: sub, role, jti, iss, aud, iat, exp.
- access tokens curtos (15 min) + refresh tokens longos (7 dias) com rotação.
- Hash de senha via bcrypt (cost 12).
- Decorator/dependency requires_role para RBAC granular.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import lru_cache
from typing import Iterable

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings


class Role(str, Enum):
    CONSULTOR = "consultor"
    ADMIN = "admin"
    ANALISTA = "analista"


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


# ---- Carregamento das chaves RSA ------------------------------------------

@lru_cache
def _private_key() -> bytes:
    return get_settings().jwt_private_key_path.read_bytes()


@lru_cache
def _public_key() -> bytes:
    return get_settings().jwt_public_key_path.read_bytes()


# ---- Senhas ---------------------------------------------------------------

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


# ---- JWT ------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def create_access_token(*, subject: str, role: Role, nome: str | None = None) -> tuple[str, str]:
    """Retorna (token_assinado, jti)."""
    settings = get_settings()
    jti = uuid.uuid4().hex
    now = _now_utc()
    payload = {
        "sub": subject,
        "role": role.value,
        "nome": nome,
        "type": TokenType.ACCESS.value,
        "jti": jti,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_access_ttl_minutes)).timestamp()),
    }
    token = jwt.encode(payload, _private_key(), algorithm="RS256")
    return token, jti


def create_refresh_token(*, subject: str, role: Role) -> tuple[str, str, datetime]:
    """Retorna (token_assinado, jti, expira_em)."""
    settings = get_settings()
    jti = secrets.token_urlsafe(32)
    now = _now_utc()
    exp = now + timedelta(days=settings.jwt_refresh_ttl_days)
    payload = {
        "sub": subject,
        "role": role.value,
        "type": TokenType.REFRESH.value,
        "jti": jti,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, _private_key(), algorithm="RS256")
    return token, jti, exp


def decode_token(token: str, *, expected_type: TokenType) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            _public_key(),
            algorithms=["RS256"],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "jti", "type"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token expirado") from e
    except jwt.InvalidTokenError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token inválido") from e

    if payload.get("type") != expected_type.value:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Tipo de token inválido")

    return payload


# ---- HTTPBearer + dependências --------------------------------------------

class Principal:
    """Identidade autenticada propagada para handlers via Depends."""

    __slots__ = ("user_id", "role", "nome", "jti")

    def __init__(self, *, user_id: str, role: Role, nome: str | None, jti: str) -> None:
        self.user_id = user_id
        self.role = role
        self.nome = nome
        self.jti = jti


_bearer = HTTPBearer(auto_error=True)


def current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> Principal:
    payload = decode_token(credentials.credentials, expected_type=TokenType.ACCESS)
    principal = Principal(
        user_id=payload["sub"],
        role=Role(payload["role"]),
        nome=payload.get("nome"),
        jti=payload["jti"],
    )
    # Propaga no request.state pra uso em middleware/audit
    request.state.principal = principal
    return principal


def requires_role(*allowed: Role):
    """
    Dependency factory para RBAC:

        @router.post("/x", dependencies=[Depends(requires_role(Role.ADMIN))])
    """
    allowed_set = set(allowed)

    def _checker(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role not in allowed_set:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={"required_roles": [r.value for r in allowed]},
            )
        return principal

    return _checker
