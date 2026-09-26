"""
Camada de criptografia para PII em repouso.

- Fernet (AES-128-CBC + HMAC-SHA256) cifra valores não-determinísticos:
  cada chamada produz ciphertext diferente. Bom para confidencialidade.

- cpf_hash() produz hash determinístico (HMAC-SHA256 com pepper) para
  permitir busca por igualdade no banco SEM expor o CPF plaintext.

Convenção:
    cliente.cpf_encrypted = encrypt_value(cpf_plaintext)
    cliente.cpf_hash      = cpf_hash(cpf_plaintext)
"""
from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class CryptoService:
    def __init__(self) -> None:
        settings = get_settings()
        self._fernet = Fernet(settings.fernet_key.encode())
        self._pepper = settings.cpf_hash_pepper.encode()

    def encrypt(self, plaintext: str | None) -> str | None:
        if plaintext is None:
            return None
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("ascii")

    def decrypt(self, ciphertext: str | None) -> str | None:
        if not ciphertext:
            return None
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except InvalidToken as e:
            raise ValueError("Token Fernet inválido — chave incorreta ou dado adulterado") from e

    def cpf_hash(self, cpf: str) -> str:
        """HMAC-SHA256 determinístico do CPF normalizado para lookup."""
        normalized = "".join(ch for ch in cpf if ch.isdigit())
        digest = hmac.new(self._pepper, normalized.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


_singleton: CryptoService | None = None


def get_crypto() -> CryptoService:
    global _singleton
    if _singleton is None:
        _singleton = CryptoService()
    return _singleton


# ---- Helpers de mascaramento (uso em DTOs e respostas) ---------------------

def mask_cpf(cpf: str | None) -> str | None:
    if not cpf or len(cpf) < 11:
        return cpf
    digits = "".join(ch for ch in cpf if ch.isdigit())
    if len(digits) != 11:
        return cpf
    return f"{digits[:3]}.***.***-{digits[-2:]}"


def mask_email(email: str | None) -> str | None:
    if not email or "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if not local:
        return email
    return f"{local[0]}***@{domain}"


def mask_telefone(telefone: str | None) -> str | None:
    if not telefone or len(telefone) < 4:
        return telefone
    return "****" + telefone[-4:]


# ---- Pseudonimização irreversível (LGPD / retention) -----------------------

def pseudonymize(identifier: str) -> str:
    """
    Mapeia identidade real para token estável e irreversível para uso em
    datasets de ML e dashboards. SHA-256(pepper || identifier).
    """
    settings = get_settings()
    digest = hashlib.sha256(settings.cpf_hash_pepper.encode() + identifier.encode()).hexdigest()
    return f"pseudo_{digest[:16]}"
