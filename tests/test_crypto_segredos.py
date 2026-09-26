"""Rotação de chave Fernet e recusa de segredo fraco em produção."""
import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from sqlalchemy import text

import app.core.crypto as crypto_mod
from app.core.config import Settings, get_settings


@pytest.fixture
def troca_chaves(monkeypatch):
    def _troca(chaves: str):
        monkeypatch.setenv("FERNET_KEYS", chaves)
        get_settings.cache_clear()
        crypto_mod._singleton = None
        return crypto_mod.get_crypto()

    yield _troca
    get_settings.cache_clear()
    crypto_mod._singleton = None


def test_rotacao_recifra_e_chave_antiga_pode_sair(db, troca_chaves):
    from app.cli.rotate_keys import rotacionar
    from app.models import Cliente

    antiga, nova = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    c = troca_chaves(antiga)
    db.add(Cliente(nome="X", cpf_encrypted=c.encrypt("12345678909"), cpf_hash=c.cpf_hash("12345678909"),
                   email_encrypted=c.encrypt("x@example.com"), regiao="SP"))
    db.commit()

    troca_chaves(f"{nova},{antiga}")
    assert rotacionar() == 1

    so_nova = troca_chaves(nova)
    cpf, email = db.execute(text("SELECT cpf_encrypted, email_encrypted FROM clientes")).one()
    assert so_nova.decrypt(cpf) == "12345678909"
    assert so_nova.decrypt(email) == "x@example.com"

    so_antiga = troca_chaves(antiga)
    with pytest.raises(ValueError):
        so_antiga.decrypt(cpf)


def test_fernet_nao_deterministico_e_detecta_adulteracao():
    c = crypto_mod.get_crypto()
    a, b = c.encrypt("12345678909"), c.encrypt("12345678909")
    assert a != b
    adulterado = a[:-4] + ("AAAA" if not a.endswith("AAAA") else "BBBB")
    with pytest.raises(ValueError):
        c.decrypt(adulterado)


BASE = dict(
    fernet_keys=Fernet.generate_key().decode(),
    cpf_hash_pepper="Zq8#pL2v!mN4rT7wY1cX6bH9jK3sD5fG",
    hmac_payload_secret="Wm3$kP9qR2tV6yB8nC1xZ4hJ7gF5dS0a",
    cors_origins="https://painel.previopls.com.br",
    _env_file=None,
)


def test_producao_aceita_segredo_forte():
    assert Settings(app_env="production", **BASE).is_prod


@pytest.mark.parametrize("campo,valor", [
    ("cpf_hash_pepper", "troque-em-producao-para-um-valor-aleatorio"),
    ("hmac_payload_secret", "curto-demais-1234"),
    ("cors_origins", "*"),
])
def test_producao_recusa_segredo_fraco(campo, valor):
    with pytest.raises(ValidationError):
        Settings(app_env="production", **{**BASE, campo: valor})


def test_producao_recusa_pepper_igual_ao_segredo_hmac():
    with pytest.raises(ValidationError):
        Settings(app_env="production", **{**BASE, "hmac_payload_secret": BASE["cpf_hash_pepper"]})
