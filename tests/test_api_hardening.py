"""Rate limit, X-Forwarded-For, HMAC anti-replay, headers e validação de entrada."""
import json
import time

import httpx
import pytest
from sqlalchemy import func, select, text
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.core.config import get_settings
from app.core.hmac_signing import assinar
from app.models import AuditAction, AuditLog
from tests.conftest import auth, login

CLIENTE = {
    "nome": "Maria Teste",
    "cpf": "123.456.789-09",
    "email": "maria.teste@example.com",
    "telefone": "+55 11 99999-8888",
    "regiao": "SP",
    "veiculo": {
        "modelo": "Ranger", "versao": "XLT", "ano": 2026, "vin": "9BFZZZ8F7NB000001",
        "placa": "ABC1D23", "data_compra": "2026-05-13", "valor_compra": "250000.00",
        "concessionaria_id": "FORD-SP-001",
    },
}


def _post_assinado(client, tokens, corpo: dict, ts: int | None = None, assinatura: str | None = None):
    body = json.dumps(corpo).encode()
    ts = ts or int(time.time())
    sig = assinatura or assinar(body, ts, get_settings().hmac_payload_secret)
    headers = {**auth(tokens), "X-Timestamp": str(ts), "X-Signature": sig, "Content-Type": "application/json"}
    return client.post("/v1/clientes", content=body, headers=headers)


# ---- rate limit ----------------------------------------------------------------

def test_limite_global_vale_pra_qualquer_rota(client, db):
    # /version nao tem @limiter.limit: na sprint 2 nunca batia em 429
    codigos = [client.get("/version").status_code for _ in range(101)]
    assert codigos[:100].count(200) == 100
    assert codigos[100] == 429


def test_health_fica_fora_do_rate_limit(client, db):
    assert all(client.get("/health").status_code == 200 for _ in range(120))


def test_login_5_por_minuto(client, db):
    codigos = [
        client.post("/v1/auth/login", json={"email": f"x{i}@ford.com", "senha": "qualquer123"}).status_code
        for i in range(6)
    ]
    assert codigos[:5] == [401] * 5
    assert codigos[5] == 429


async def _ip_visto(trusted: str, conexao: str, xff: str) -> str:
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": scope["client"][0].encode()})

    transport = httpx.ASGITransport(app=ProxyHeadersMiddleware(app, trusted_hosts=trusted), client=(conexao, 5000))
    async with httpx.AsyncClient(transport=transport, base_url="http://api") as c:
        return (await c.get("/", headers={"X-Forwarded-For": xff})).text


@pytest.mark.anyio
async def test_xff_forjado_so_funcionava_com_trust_em_todos():
    # sprint 2: uvicorn com --forwarded-allow-ips=* aceitava o IP que o cliente escolhesse
    assert await _ip_visto("*", "172.28.0.10", "6.6.6.6, 200.1.1.1") == "6.6.6.6"
    # agora: so o nginx e confiavel e ele sobrescreve o XFF com $remote_addr
    assert await _ip_visto("172.28.0.10", "172.28.0.10", "200.1.1.1") == "200.1.1.1"
    # quem conecta direto (sem ser o nginx) nao consegue trocar o proprio IP
    assert await _ip_visto("172.28.0.10", "172.28.0.99", "6.6.6.6") == "172.28.0.99"


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---- HMAC ----------------------------------------------------------------------

def test_cadastro_assinado_passa_e_pii_fica_cifrada(client, usuarios, db):
    tokens = login(client, "admin")
    r = _post_assinado(client, tokens, CLIENTE)
    assert r.status_code == 201, r.text
    cliente = r.json()["cliente"]
    assert cliente["cpf_masked"] == "123.***.***-09"
    assert "maria.teste" not in json.dumps(r.json())

    cpf_em_repouso = db.execute(text("SELECT cpf_encrypted, email_encrypted FROM clientes")).one()
    assert "12345678909" not in cpf_em_repouso[0]
    assert "maria" not in (cpf_em_repouso[1] or "")


def test_replay_da_mesma_requisicao_assinada_e_recusado(client, usuarios, db):
    tokens = login(client, "admin")
    ts = int(time.time())
    assert _post_assinado(client, tokens, CLIENTE, ts=ts).status_code == 201
    r = _post_assinado(client, tokens, CLIENTE, ts=ts)
    assert r.status_code == 401
    assert "replay" in r.text
    db.expire_all()
    assert db.scalar(
        select(func.count()).select_from(AuditLog).where(AuditLog.action == AuditAction.SIGNATURE_REJECTED)
    ) == 1


@pytest.mark.parametrize("caso", ["sem_headers", "assinatura_errada", "timestamp_velho"])
def test_assinatura_invalida(client, usuarios, db, caso):
    tokens = login(client, "admin")
    if caso == "sem_headers":
        r = client.post("/v1/clientes", headers=auth(tokens), json=CLIENTE)
    elif caso == "assinatura_errada":
        r = _post_assinado(client, tokens, CLIENTE, assinatura="0" * 64)
    else:
        r = _post_assinado(client, tokens, CLIENTE, ts=int(time.time()) - 3600)
    assert r.status_code == 401
    db.expire_all()
    assert db.scalar(
        select(func.count()).select_from(AuditLog).where(AuditLog.action == AuditAction.SIGNATURE_REJECTED)
    ) == 1


# ---- entrada e headers -----------------------------------------------------------

def test_campo_extra_e_cpf_invalido_viram_422(client, usuarios):
    tokens = login(client, "admin")
    assert _post_assinado(client, tokens, {**CLIENTE, "perfil": "fiel"}).status_code == 422
    assert _post_assinado(client, tokens, {**CLIENTE, "cpf": "abc"}).status_code == 422
    vin_com_o = {**CLIENTE, "veiculo": {**CLIENTE["veiculo"], "vin": "9BFZZZ8F7NB00000O"}}
    assert _post_assinado(client, tokens, vin_com_o).status_code == 422


def test_filtro_com_sql_injection_vira_422(client, usuarios):
    tokens = login(client, "consultor")
    r = client.get("/v1/leads", params={"prioridade": "alta' OR '1'='1"}, headers=auth(tokens))
    assert r.status_code == 422


def test_request_id_malicioso_e_trocado(client, db):
    r = client.get("/health", headers={"X-Request-Id": 'abc" level="critical'})
    assert r.headers["x-request-id"] != 'abc" level="critical'
    assert len(r.headers["x-request-id"]) == 32
    ok = client.get("/health", headers={"X-Request-Id": "req-0123456789"})
    assert ok.headers["x-request-id"] == "req-0123456789"


def test_headers_de_seguranca(client, db):
    r = client.get("/version")
    h = r.headers
    assert h["strict-transport-security"].startswith("max-age=31536000")
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["content-security-policy"].startswith("default-src 'none'")
    assert "server" not in {k.lower() for k in h.keys()} or "uvicorn" not in h.get("server", "")


def test_erro_interno_nao_vaza_stack_trace(client, usuarios):
    tokens = login(client, "consultor")
    r = client.get("/v1/leads/nao-e-uuid", headers=auth(tokens))
    assert r.status_code == 422
    assert "Traceback" not in r.text
