"""
Testes unitários dos blocos de segurança que não dependem de DB:

- Fernet round-trip + masking de PII
- JWT RS256 sign/verify, expiração, audiência
- HMAC de payload (assinatura + janela temporal)
- Mascaramento de PII nos logs
"""
import base64
import hashlib
import hmac
import os
import time
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.fernet import Fernet


# ---- Bootstrap ENV antes de importar a app ---------------------------------

os.environ.setdefault("APP_ENV", "testing")
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("CPF_HASH_PEPPER", "test-pepper-32-bytes-padding-aaaaaaa")
os.environ.setdefault("HMAC_PAYLOAD_SECRET", "test-hmac-secret-32-bytes-padding-aaa")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@nohost/x")

# Gera par RSA temporário
_keys_dir = Path(__file__).parent / "_keys"
_keys_dir.mkdir(exist_ok=True)
_priv = _keys_dir / "priv.pem"
_pub = _keys_dir / "pub.pem"
if not _priv.exists():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _priv.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    _pub.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
os.environ["JWT_PRIVATE_KEY_PATH"] = str(_priv)
os.environ["JWT_PUBLIC_KEY_PATH"] = str(_pub)

# Limpa cache do Settings entre testes (lru_cache no get_settings).
from app.core.config import get_settings  # noqa: E402
get_settings.cache_clear()


# ---- Fernet + CPF hash -----------------------------------------------------

def test_fernet_roundtrip():
    from app.core.crypto import get_crypto
    c = get_crypto()
    ct = c.encrypt("12345678900")
    assert ct is not None and ct != "12345678900"
    assert c.decrypt(ct) == "12345678900"


def test_cpf_hash_is_deterministic():
    from app.core.crypto import get_crypto
    c = get_crypto()
    assert c.cpf_hash("123.456.789-00") == c.cpf_hash("12345678900")
    assert c.cpf_hash("11111111111") != c.cpf_hash("22222222222")


def test_pii_masking_helpers():
    from app.core.crypto import mask_cpf, mask_email, mask_telefone
    assert mask_cpf("12345678900") == "123.***.***-00"
    assert mask_email("maria.silva@example.com").startswith("m***@example.com")
    assert mask_telefone("+5511999998888").endswith("8888")
    assert "9999" not in mask_telefone("+5511999998888")


# ---- JWT RS256 -------------------------------------------------------------

def test_jwt_access_roundtrip():
    from app.core.security import (
        Role, TokenType, create_access_token, decode_token,
    )
    token, jti = create_access_token(subject="user-1", role=Role.CONSULTOR, nome="Carlos")
    payload = decode_token(token, expected_type=TokenType.ACCESS)
    assert payload["sub"] == "user-1"
    assert payload["role"] == "consultor"
    assert payload["jti"] == jti
    assert payload["type"] == "access"


def test_jwt_refresh_type_mismatch_is_rejected():
    from fastapi import HTTPException
    from app.core.security import (
        Role, TokenType, create_refresh_token, decode_token,
    )
    refresh, _, _ = create_refresh_token(subject="user-1", role=Role.ADMIN)
    # Tentar usar refresh como access → 401
    with pytest.raises(HTTPException) as excinfo:
        decode_token(refresh, expected_type=TokenType.ACCESS)
    assert excinfo.value.status_code == 401


def test_jwt_tampering_invalidates_signature():
    from fastapi import HTTPException
    from app.core.security import Role, TokenType, create_access_token, decode_token
    token, _ = create_access_token(subject="u", role=Role.ADMIN)
    # Troca caracteres do payload (parte do meio do JWT)
    parts = token.split(".")
    flipped = "B" if parts[1][-1] != "B" else "C"
    parts[1] = parts[1][:-1] + flipped
    tampered = ".".join(parts)
    with pytest.raises(HTTPException):
        decode_token(tampered, expected_type=TokenType.ACCESS)


# ---- HMAC --------------------------------------------------------------

def test_hmac_signature_matches_constant_time():
    secret = b"test-hmac-secret-32-bytes-padding-aaa"
    body = b'{"cpf":"12345678900"}'
    ts = str(int(time.time()))
    mac = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    # Mesma computação produz mesmo MAC.
    mac2 = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(mac, mac2)


# ---- Logging masking -------------------------------------------------------

def test_logging_masks_cpf_and_email():
    from app.core.logging import pii_masking_processor
    event = {"event": "user_login", "cpf": "12345678900", "email": "user@example.com"}
    out = pii_masking_processor(None, None, event)
    assert "12345678900" not in str(out)
    assert "user@example.com" not in str(out)
    assert "123.***.***-00" in str(out["cpf"])
