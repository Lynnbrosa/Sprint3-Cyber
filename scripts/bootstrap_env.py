"""
Cria o .env de desenvolvimento com segredo aleatorio em tudo. Nao existe senha
padrao no repositorio: cada clone gera as suas.

    python scripts/bootstrap_env.py            # cria .env se nao existir
    python scripts/bootstrap_env.py --force    # regera (invalida dados cifrados!)

Sem python no host:
    docker run --rm -v "$PWD:/w" -w /w python:3.12-slim python scripts/bootstrap_env.py
"""
import argparse
import base64
import os
import secrets
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def fernet_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def senha(n: int = 18) -> str:
    return secrets.token_urlsafe(n)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    destino = RAIZ / ".env"
    if destino.exists() and not a.force:
        print(".env ja existe (use --force para regerar)")
        return 0

    modelo = (RAIZ / ".env.example").read_text(encoding="utf-8")
    valores = {
        "POSTGRES_PASSWORD": senha(),
        "FERNET_KEYS": fernet_key(),
        "CPF_HASH_PEPPER": secrets.token_urlsafe(36),
        "HMAC_PAYLOAD_SECRET": secrets.token_urlsafe(36),
        "METRICS_TOKEN": secrets.token_urlsafe(24),
        "GRAFANA_ADMIN_PASSWORD": senha(),
        "SEED_ADMIN_PASSWORD": senha(12),
        "SEED_CONSULTOR_PASSWORD": senha(12),
        "SEED_ANALISTA_PASSWORD": senha(12),
    }
    linhas = []
    for linha in modelo.splitlines():
        chave = linha.split("=", 1)[0].strip()
        if chave in valores and linha.strip().endswith("="):
            linha = f"{chave}={valores[chave]}"
        linhas.append(linha)
    destino.write_text("\n".join(linhas) + "\n", encoding="utf-8", newline="\n")
    # o prometheus le o token como secret de arquivo (container read_only nao aceita secret por env)
    segredos = RAIZ / ".secrets"
    segredos.mkdir(exist_ok=True)
    (segredos / "metrics_token").write_text(valores["METRICS_TOKEN"], encoding="utf-8")
    for arq in (destino, segredos / "metrics_token"):
        try:
            os.chmod(arq, 0o600)
        except OSError:
            pass

    print(f".env criado em {destino}")
    print("usuarios de demo (so em desenvolvimento):")
    for papel in ("ADMIN", "CONSULTOR", "ANALISTA"):
        print(f"  {papel.lower()}@ford.com / {valores[f'SEED_{papel}_PASSWORD']}")
    print(f"grafana: admin / {valores['GRAFANA_ADMIN_PASSWORD']}  (http://127.0.0.1:3300)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
