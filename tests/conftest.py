"""
Ambiente de teste. As variaveis entram antes de importar a app porque o
Settings e o engine sao criados no import.

Os testes de integracao precisam de um Postgres (TEST_DATABASE_URL). Sem banco
eles sao pulados e so os unitarios rodam. No CI o banco vem de um service container.
"""
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

TEST_DB = os.environ.get("TEST_DATABASE_URL", "postgresql+psycopg://teste:teste@127.0.0.1:55432/teste")
KEYS = Path(__file__).parent / "_keys"

os.environ["APP_ENV"] = "testing"
os.environ["DATABASE_URL"] = TEST_DB
os.environ.setdefault("FERNET_KEYS", Fernet.generate_key().decode())
os.environ.setdefault("FERNET_KEY", os.environ["FERNET_KEYS"].split(",")[0])
os.environ.setdefault("CPF_HASH_PEPPER", "pepper-de-teste-com-mais-de-32-bytes-aaaa")
os.environ.setdefault("HMAC_PAYLOAD_SECRET", "segredo-hmac-de-teste-com-32-bytes-aaaa")
os.environ["JWT_PRIVATE_KEY_PATH"] = str(KEYS / "priv.pem")
os.environ["JWT_PUBLIC_KEY_PATH"] = str(KEYS / "pub.pem")
os.environ["SEED_DEFAULT_USERS"] = "false"
os.environ["RATE_LIMIT_GLOBAL"] = "100/minute"
os.environ["RATE_LIMIT_LOGIN"] = "5/minute"
os.environ["LOG_FILE"] = ""

from app.core.config import get_settings  # noqa: E402

get_settings.cache_clear()

from app.core.security import ensure_jwt_keys  # noqa: E402

ensure_jwt_keys()

SENHAS = {"admin": "senha-admin-teste", "consultor": "senha-consultor-teste", "analista": "senha-analista-teste"}


def _db_disponivel() -> bool:
    from sqlalchemy import create_engine, text

    try:
        with create_engine(TEST_DB).connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def banco():
    if not _db_disponivel():
        pytest.skip("Postgres de teste indisponivel (TEST_DATABASE_URL)")
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parent.parent / "alembic"))
    from sqlalchemy import create_engine, text

    # schema do zero: downgrade com linha de auditoria nova esbarraria no CHECK antigo
    with create_engine(TEST_DB).begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    command.upgrade(cfg, "head")
    yield
    from app.db.session import engine

    engine.dispose()


@pytest.fixture()
def db(banco):
    from sqlalchemy import text

    from app.core.ratelimit import limiter
    from app.db.session import SessionLocal, engine

    with engine.begin() as conn:
        tabelas = conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'alembic_version'"
        )).scalars().all()
        if tabelas:
            conn.execute(text("TRUNCATE " + ", ".join(tabelas) + " CASCADE"))
    limiter.reset()

    from app.services import alert_service

    alert_service._login_failures._timestamps.clear()
    alert_service._query_counter._timestamps.clear()

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def usuarios(db):
    from app.db.seed import ensure_user
    from app.models import RolePapel, Usuario

    for papel in ("admin", "consultor", "analista"):
        ensure_user(db, nome=papel.title(), email=f"{papel}@ford.com", senha=SENHAS[papel], papel=RolePapel(papel))
    return {u.papel.value: u for u in db.query(Usuario).all()}


@pytest.fixture()
def client(db):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app, base_url="https://testserver") as c:
        yield c


def login(client, papel: str) -> dict:
    r = client.post("/v1/auth/login", json={"email": f"{papel}@ford.com", "senha": SENHAS[papel]})
    assert r.status_code == 200, r.text
    return r.json()


def auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}
