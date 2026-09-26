"""
Gera tráfego pela borda (nginx 8443) pra popular dashboards e disparar alertas:
uso normal (cadastro assinado, consulta e atualização de leads) e os ataques
que os controles precisam barrar. Cada ataque imprime o que aconteceu.

    docker compose --profile demo run --rm trafego [--fase normal|ataques|tudo]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import string
import time

import httpx

from app.core.hmac_signing import assinar

BASE = os.environ.get("DEMO_BASE_URL", "https://localhost:8443")
CA = os.environ.get("DEMO_CA", "/certs/ca.crt")
SENHAS = {
    "admin": os.environ.get("SEED_ADMIN_PASSWORD", ""),
    "consultor": os.environ.get("SEED_CONSULTOR_PASSWORD", ""),
    "analista": os.environ.get("SEED_ANALISTA_PASSWORD", ""),
}
SEGREDO_HMAC = os.environ.get("HMAC_PAYLOAD_SECRET", "")
MODELOS = [("Ranger", "XLT"), ("Ranger", "Raptor"), ("Territory", "Titanium"), ("Maverick", "Lariat"),
           ("Bronco Sport", "Wildtrak"), ("Transit", "Van")]
REGIOES = ["SP", "RJ", "MG", "PR", "RS", "BA", "PE", "GO"]
VIN_CHARS = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"


def _cliente() -> httpx.Client:
    return httpx.Client(base_url=BASE, verify=CA, timeout=10, headers={"X-Client": "web"})


def _login(c: httpx.Client, papel: str) -> dict:
    r = c.post("/v1/auth/login", json={"email": f"{papel}@ford.com", "senha": SENHAS[papel]})
    r.raise_for_status()
    return r.json()


def _h(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _cpf() -> str:
    base = [random.randint(0, 9) for _ in range(9)]
    for _ in range(2):
        soma = sum(v * p for v, p in zip(base, range(len(base) + 1, 1, -1)))
        base.append((soma * 10 % 11) % 10)
    return "".join(map(str, base))


def _novo_cliente() -> dict:
    modelo, versao = random.choice(MODELOS)
    return {
        "nome": random.choice(["Ana", "Bruno", "Carla", "Diego", "Elisa", "Fabio", "Gabi", "Hugo"]) + " " +
                random.choice(["Souza", "Lima", "Alves", "Rocha", "Nunes", "Prado"]),
        "cpf": _cpf(),
        "email": "".join(random.choices(string.ascii_lowercase, k=8)) + "@example.com",
        "telefone": f"+55119{random.randint(10000000, 99999999)}",
        "regiao": random.choice(REGIOES),
        "veiculo": {
            "modelo": modelo, "versao": versao, "ano": random.choice([2025, 2026]),
            "vin": "9BF" + "".join(random.choices(VIN_CHARS, k=14)),
            "data_compra": "2026-09-2" + str(random.randint(0, 5)),
            "valor_compra": f"{random.randint(180, 520)}000.00",
            "concessionaria_id": f"FORD-{random.choice(REGIOES)}-{random.randint(1, 40):03d}",
        },
    }


def _post_assinado(c, tokens, corpo: dict, ts: int | None = None):
    body = json.dumps(corpo).encode()
    ts = ts or int(time.time())
    headers = {**_h(tokens), "Content-Type": "application/json", "X-Timestamp": str(ts),
               "X-Signature": assinar(body, ts, SEGREDO_HMAC)}
    return c.post("/v1/clientes", content=body, headers=headers), body, ts


def normal(n: int = 25) -> None:
    with _cliente() as c:
        admin = _login(c, "admin")
        criados = 0
        for _ in range(n):
            r, _, _ = _post_assinado(c, admin, _novo_cliente())
            criados += r.status_code == 201
            time.sleep(0.3)
        print(f"[normal] {criados}/{n} cadastros assinados aceitos (classificacao D0 + lead)")

        consultor = _login(c, "consultor")
        leads = c.get("/v1/leads", params={"per_page": 20}, headers={**_h(consultor), "X-Client": "mobile"}).json()
        for item in leads.get("items", [])[:8]:
            c.get(f"/v1/leads/{item['id']}", headers=_h(consultor))
            c.patch(f"/v1/leads/{item['id']}", headers=_h(consultor),
                    json={"status": random.choice(["agendado", "sem-contato"]), "observacao": "contato pelo app"})
            time.sleep(0.2)
        print(f"[normal] consultor abriu e atualizou {min(8, len(leads.get('items', [])))} leads")

        analista = _login(c, "analista")
        c.get("/v1/admin/audit-log", headers=_h(analista))
        print("[normal] analista consultou a trilha de auditoria")


def _j(r: httpx.Response) -> dict:
    try:
        return r.json()
    except ValueError:
        return {}


def _forca_bruta(c: httpx.Client) -> None:
    # 1. forca bruta. em rajada o nginx (5 req/min por IP no login) barra quase tudo com 429;
    # aqui o atacante e paciente e fica abaixo do limite: 1 tentativa a cada 12,5 s.
    # 6 no admin (lockout na 6a) e depois spray em outras contas
    rajada = [c.post("/v1/auth/login", json={"email": "admin@ford.com", "senha": f"chute{i:03d}"}).status_code
              for i in range(10)]
    print(f"[forca-bruta] rajada de 10 no admin: {rajada} (429 = nginx/slowapi)")
    time.sleep(61)
    alvos = ["admin@ford.com"] * 6 + ["consultor@ford.com", "analista@ford.com", "gerente@ford.com",
                                      "ti@ford.com", "financeiro@ford.com", "suporte@ford.com", "rh@ford.com"]
    lento = []
    for i, email in enumerate(alvos):
        r = c.post("/v1/auth/login", json={"email": email, "senha": f"Ford@{2020 + i}"})
        lento.append((email.split("@")[0], r.status_code, _j(r).get("error", {}).get("message", "")[:24]))
        time.sleep(12.5)
    print(f"[forca-bruta] lenta ({len(alvos)} tentativas): {lento}")

    # 2. XFF forjado nao muda o bucket do rate limit
    forjados = [c.get("/version", headers={"X-Forwarded-For": f"10.9.{i}.{i}"}).status_code for i in range(130)]
    print(f"[xff-forjado] 130 requisicoes com X-Forwarded-For diferente: {forjados.count(429)} barradas com 429")
    time.sleep(61)


def ataques(pular_forca_bruta: bool = False) -> None:
    with _cliente() as c:
        if not pular_forca_bruta:
            _forca_bruta(c)

        consultor = _login(c, "consultor")
        # 3. escalacao de privilegio: consultor em rota de admin
        negados = [c.get("/v1/admin/audit-log", headers=_h(consultor)).status_code for _ in range(8)]
        negados.append(c.post("/v1/admin/usuarios/00000000-0000-0000-0000-000000000000/revogar-sessoes",
                              headers=_h(consultor)).status_code)
        print(f"[rbac] consultor tentando rotas de admin: {negados}")

        # 4. token forjado / alg none / lixo
        # token alg=none forjado de proposito (sem assinatura), e o ataque que a api tem que recusar
        falsos = ["eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4Iiwicm9sZSI6ImFkbWluIn0.", "lixo", consultor["refresh_token"]]  # gitleaks:allow
        rec = []
        for t in falsos * 8:
            rec.append(c.get("/v1/leads", headers={"Authorization": f"Bearer {t}"}).status_code)
            time.sleep(0.4)
        print(f"[jwt] 24 tokens forjados/errados: {sorted(set(rec))}")

        time.sleep(30)  # deixa o balde do rate limit esvaziar antes da proxima fase
        # 5. roubo de sessao: refresh reutilizado derruba a familia
        vitima = _login(c, "consultor")
        novo = _j(c.post("/v1/auth/refresh", json={"refresh_token": vitima["refresh_token"]}))
        reuso = c.post("/v1/auth/refresh", json={"refresh_token": vitima["refresh_token"]})
        legit = c.post("/v1/auth/refresh", json={"refresh_token": novo.get("refresh_token", "x" * 40)})
        print(f"[sessao] reuso do refresh antigo: {reuso.status_code}; refresh legitimo depois disso: {legit.status_code}")

        # 6. webhook adulterado e replay
        admin = _login(c, "admin")
        r1, body, ts = _post_assinado(c, admin, _novo_cliente())
        replay = c.post("/v1/clientes", content=body, headers={**_h(admin), "Content-Type": "application/json",
                        "X-Timestamp": str(ts), "X-Signature": assinar(body, ts, SEGREDO_HMAC)})
        adulterado = c.post("/v1/clientes", content=body.replace(b'"SP"', b'"RJ"'),
                            headers={**_h(admin), "Content-Type": "application/json", "X-Timestamp": str(ts),
                                     "X-Signature": assinar(body, ts, SEGREDO_HMAC)})
        velho = _post_assinado(c, admin, _novo_cliente(), ts=int(time.time()) - 3600)[0]
        sem = c.post("/v1/clientes", json=_novo_cliente(), headers=_h(admin))
        print(f"[hmac] original {r1.status_code}; replay {replay.status_code}; corpo adulterado "
              f"{adulterado.status_code}; timestamp velho {velho.status_code}; sem assinatura {sem.status_code}")

        # 7. consulta massiva (exfiltracao) com o proprio consultor
        time.sleep(20)
        consultor = _login(c, "consultor")
        mass = []
        for i in range(60):
            mass.append(c.get("/v1/leads", params={"page": i % 5 + 1}, headers=_h(consultor)).status_code)
            time.sleep(0.55)  # abaixo do limite do nginx: quem exfiltra devagar passa, quem detecta e o alerta
        print(f"[exfiltracao] 60 listagens de leads em sequencia: {mass.count(200)} ok, {mass.count(429)} barradas")

        # 8. injecao em filtro e campo extra (mass assignment)
        sqli = c.get("/v1/leads", params={"prioridade": "alta' OR '1'='1"}, headers=_h(consultor)).status_code
        extra = _post_assinado(c, admin, {**_novo_cliente(), "perfil": "fiel", "is_admin": True})[0].status_code
        print(f"[entrada] SQLi no filtro: {sqli}; campo extra no cadastro: {extra}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fase", default="tudo", choices=["normal", "ataques", "tudo"])
    ap.add_argument("--n", type=int, default=25)
    ap.add_argument("--pular-forca-bruta", action="store_true")
    a = ap.parse_args()
    if a.fase in ("normal", "tudo"):
        normal(a.n)
    if a.fase in ("ataques", "tudo"):
        ataques(a.pular_forca_bruta)


if __name__ == "__main__":
    main()
