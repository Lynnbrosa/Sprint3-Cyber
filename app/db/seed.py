"""
Criação de usuários. A API não expõe endpoint de gestão de usuário (menos superfície);
usuário entra por três caminhos, todos idempotentes por email:

1. seed_default_users(): admin/consultor/analista de demo, só fora de produção.
   As senhas vêm de SEED_*_PASSWORD no .env; sem senha configurada o usuário é pulado.
2. bootstrap_admin(): primeiro admin de produção via BOOTSTRAP_ADMIN_EMAIL/PASSWORD.
3. CLI: python -m app.db.seed --email x@ford.com --papel consultor
   (a senha vem de NEW_USER_PASSWORD ou do prompt, nunca de argumento: argumento vaza no ps/histórico)
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import hash_password
from app.models import RolePapel, Usuario


log = get_logger(__name__)

MIN_PASSWORD_LENGTH = 6  # mesmo mínimo do LoginRequest
MIN_PROD_PASSWORD_LENGTH = 12


def ensure_user(db: Session, *, nome: str, email: str, senha: str, papel: RolePapel) -> bool:
    email = email.strip().lower()
    minimo = MIN_PROD_PASSWORD_LENGTH if get_settings().is_prod else MIN_PASSWORD_LENGTH
    if len(senha) < minimo:
        raise ValueError(f"senha precisa de pelo menos {minimo} caracteres")
    if db.scalar(select(Usuario.id).where(Usuario.email == email)) is not None:
        return False
    db.add(Usuario(nome=nome.strip() or email, email=email, senha_hash=hash_password(senha), papel=papel))
    db.commit()
    log.info("seed.user_created", email=email, papel=papel.value)
    return True


def seed_default_users(db: Session) -> int:
    s = get_settings()
    demo = (
        ("Admin Ford", "admin@ford.com", s.seed_admin_password, RolePapel.ADMIN),
        ("Carlos Consultor", "consultor@ford.com", s.seed_consultor_password, RolePapel.CONSULTOR),
        ("Ana Analista", "analista@ford.com", s.seed_analista_password, RolePapel.ANALISTA),
    )
    created = 0
    for nome, email, senha, papel in demo:
        if not senha:
            log.info("seed.user_skipped", email=email, motivo="senha nao configurada")
            continue
        if ensure_user(db, nome=nome, email=email, senha=senha, papel=papel):
            created += 1
    return created


def bootstrap_admin(db: Session) -> bool:
    s = get_settings()
    if not s.bootstrap_admin_email or not s.bootstrap_admin_password:
        return False
    return ensure_user(db, nome=s.bootstrap_admin_name, email=s.bootstrap_admin_email,
                       senha=s.bootstrap_admin_password, papel=RolePapel.ADMIN)


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.db.seed", description="Cria um usuário (idempotente).")
    parser.add_argument("--email", required=True)
    parser.add_argument("--papel", required=True, choices=[p.value for p in RolePapel])
    parser.add_argument("--nome", default="")
    args = parser.parse_args(argv)

    senha = os.environ.get("NEW_USER_PASSWORD") or getpass.getpass("senha: ")
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        try:
            created = ensure_user(db, nome=args.nome, email=args.email, senha=senha, papel=RolePapel(args.papel))
        except ValueError as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 2
    print("criado" if created else "ja existia")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
