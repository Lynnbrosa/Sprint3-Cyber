"""Autenticação, sessão e RBAC contra Postgres de verdade (cada teste parte do banco vazio)."""
import time

import jwt
import pytest
from sqlalchemy import func, select

from app.models import AuditAction, AuditLog, LoginAttempt, RefreshToken
from tests.conftest import SENHAS, auth, login


def _acoes(db, acao: AuditAction) -> int:
    db.expire_all()
    return db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == acao)) or 0


# ---- login e lockout --------------------------------------------------------

def test_login_ok_devolve_par_de_tokens(client, usuarios, db):
    tokens = login(client, "consultor")
    assert tokens["role"] == "consultor"
    assert tokens["access_expires_in"] == 15 * 60
    assert _acoes(db, AuditAction.LOGIN_SUCCESS) == 1


def test_senha_errada_401_e_falha_fica_registrada(client, usuarios, db):
    r = client.post("/v1/auth/login", json={"email": "consultor@ford.com", "senha": "errada123"})
    assert r.status_code == 401
    # na sprint 2 o rollback apagava estes dois registros
    assert _acoes(db, AuditAction.LOGIN_FAILED) == 1
    assert db.scalar(select(func.count()).select_from(LoginAttempt)) == 1


def test_lockout_apos_5_falhas_bloqueia_ate_senha_certa(client, usuarios, db):
    for _ in range(5):
        r = client.post("/v1/auth/login", json={"email": "admin@ford.com", "senha": "chute-errado"})
        assert r.status_code == 401
    client.app.state.limiter.reset()  # isola o lockout do rate limit de login

    r = client.post("/v1/auth/login", json={"email": "admin@ford.com", "senha": SENHAS["admin"]})
    assert r.status_code == 401
    assert "bloqueada" in r.json()["error"]["message"]
    assert _acoes(db, AuditAction.LOGIN_LOCKED) >= 1


def test_lockout_ignora_maiusculas_no_email(client, usuarios, db):
    for i in range(5):
        email = "Admin@Ford.com" if i % 2 else "ADMIN@ford.COM"
        client.post("/v1/auth/login", json={"email": email, "senha": "chute-errado"})
    client.app.state.limiter.reset()
    r = client.post("/v1/auth/login", json={"email": "admin@ford.com", "senha": SENHAS["admin"]})
    assert r.status_code == 401


def test_usuario_inexistente_responde_igual_senha_errada(client, usuarios):
    a = client.post("/v1/auth/login", json={"email": "ninguem@ford.com", "senha": "qualquer123"})
    b = client.post("/v1/auth/login", json={"email": "consultor@ford.com", "senha": "qualquer123"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


# ---- autenticação e RBAC ----------------------------------------------------

def test_sem_token_401_com_www_authenticate(client, usuarios):
    r = client.get("/v1/leads")
    assert r.status_code == 401
    assert r.headers.get("www-authenticate", "").startswith("Bearer")


MATRIZ = [
    # (metodo, rota, papel, status esperado)
    ("GET", "/v1/leads", "consultor", 200),
    ("GET", "/v1/leads", "analista", 200),
    ("GET", "/v1/leads", "admin", 200),
    ("GET", "/v1/admin/audit-log", "consultor", 403),
    ("GET", "/v1/admin/audit-log", "analista", 200),
    ("GET", "/v1/admin/audit-log", "admin", 200),
    ("POST", "/v1/llm-assist", "consultor", 403),
    ("POST", "/v1/llm-assist", "analista", 200),
    ("POST", "/v1/clientes", "consultor", 403),
    ("POST", "/v1/clientes", "analista", 403),
]


@pytest.mark.parametrize("metodo,rota,papel,esperado", MATRIZ)
def test_matriz_rbac(client, usuarios, metodo, rota, papel, esperado):
    tokens = login(client, papel)
    corpo = {"prompt": "cliente de alto valor"} if "llm" in rota else ({} if metodo == "POST" else None)
    r = client.request(metodo, rota, headers=auth(tokens), json=corpo)
    assert r.status_code == esperado, r.text


def test_403_por_papel_vira_forbidden_access_na_trilha(client, usuarios, db):
    tokens = login(client, "consultor")
    r = client.get("/v1/admin/audit-log", headers=auth(tokens))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"
    assert _acoes(db, AuditAction.FORBIDDEN_ACCESS) == 1


def test_analista_nao_altera_lead(client, usuarios):
    tokens = login(client, "analista")
    r = client.patch("/v1/leads/00000000-0000-0000-0000-000000000001", headers=auth(tokens),
                     json={"status": "agendado"})
    assert r.status_code == 403


# ---- JWT ---------------------------------------------------------------------

def test_token_alg_none_e_kid_desconhecido_sao_recusados(client, usuarios):
    forjado = jwt.encode({"sub": "x", "role": "admin", "type": "access"}, key=None, algorithm="none")
    assert client.get("/v1/leads", headers={"Authorization": f"Bearer {forjado}"}).status_code == 401

    tokens = login(client, "admin")
    header, payload, assinatura = tokens["access_token"].split(".")
    outro_kid = jwt.utils.base64url_encode(b'{"alg":"RS256","kid":"0000000000000000","typ":"JWT"}').decode()
    r = client.get("/v1/leads", headers={"Authorization": f"Bearer {outro_kid}.{payload}.{assinatura}"})
    assert r.status_code == 401


def test_refresh_rotaciona_e_o_antigo_morre(client, usuarios):
    t1 = login(client, "consultor")
    r = client.post("/v1/auth/refresh", json={"refresh_token": t1["refresh_token"]})
    assert r.status_code == 200
    t2 = r.json()
    assert t2["refresh_token"] != t1["refresh_token"]
    assert client.get("/v1/leads", headers=auth(t2)).status_code == 200


def test_reuso_de_refresh_derruba_todas_as_sessoes(client, usuarios, db):
    t1 = login(client, "consultor")
    t2 = client.post("/v1/auth/refresh", json={"refresh_token": t1["refresh_token"]}).json()

    # atacante reaproveita o refresh antigo
    r = client.post("/v1/auth/refresh", json={"refresh_token": t1["refresh_token"]})
    assert r.status_code == 401
    assert _acoes(db, AuditAction.REFRESH_REUSE_DETECTED) == 1

    # o refresh legitimo (t2) tambem morreu: a familia inteira foi revogada
    assert client.post("/v1/auth/refresh", json={"refresh_token": t2["refresh_token"]}).status_code == 401
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(RefreshToken).where(RefreshToken.revoked.is_(False))) == 0


def test_logout_invalida_o_access_na_hora(client, usuarios):
    tokens = login(client, "consultor")
    assert client.get("/v1/leads", headers=auth(tokens)).status_code == 200
    r = client.post("/v1/auth/logout", headers=auth(tokens), json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 204
    r = client.get("/v1/leads", headers=auth(tokens))
    assert r.status_code == 401
    assert "revogado" in r.json()["error"]["message"]


def test_kill_switch_do_admin_corta_sessao_ativa(client, usuarios, db):
    vitima = login(client, "consultor")
    time.sleep(1.1)  # iat e em segundos inteiros
    admin = login(client, "admin")
    alvo = usuarios["consultor"].id
    r = client.post(f"/v1/admin/usuarios/{alvo}/revogar-sessoes", headers=auth(admin))
    assert r.status_code == 200
    assert r.json()["refresh_revogados"] == 1
    assert client.get("/v1/leads", headers=auth(vitima)).status_code == 401
    assert client.post("/v1/auth/refresh", json={"refresh_token": vitima["refresh_token"]}).status_code == 401
    assert _acoes(db, AuditAction.SESSIONS_REVOKED) == 1


def test_kill_switch_so_admin(client, usuarios):
    consultor = login(client, "consultor")
    alvo = usuarios["admin"].id
    assert client.post(f"/v1/admin/usuarios/{alvo}/revogar-sessoes", headers=auth(consultor)).status_code == 403
