"""
Rotina mensal de auditoria de permissões (menor privilégio, LGPD art. 46).

    docker compose exec api python -m app.cli.auditoria_permissoes [--dias-inativo 90] [--saida relatorio.md]

Aponta: quantos admins existem, contas sem login há N dias (candidatas a
desativar), quem tem sessão ativa, e quem bateu em 403 no período (tentou
usar permissão que não tem). O relatório vai pro responsável de segurança,
que decide e registra a decisão no ticket da revisão.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models import AuditAction, AuditLog, RefreshToken, Usuario

MAX_ADMINS = 3


def gerar(db: Session, dias_inativo: int = 90) -> tuple[str, list[str]]:
    agora = datetime.now(timezone.utc)
    corte = agora - timedelta(days=dias_inativo)
    pendencias: list[str] = []

    ultimo_login = dict(db.execute(
        select(AuditLog.actor_id, func.max(AuditLog.occurred_at))
        .where(AuditLog.action == AuditAction.LOGIN_SUCCESS)
        .group_by(AuditLog.actor_id)
    ).all())
    sessoes = dict(db.execute(
        select(RefreshToken.usuario_id, func.count())
        .where(RefreshToken.revoked.is_(False), RefreshToken.expires_at > agora)
        .group_by(RefreshToken.usuario_id)
    ).all())
    negados = dict(db.execute(
        select(AuditLog.actor_id, func.count())
        .where(AuditLog.action == AuditAction.FORBIDDEN_ACCESS, AuditLog.occurred_at > corte)
        .group_by(AuditLog.actor_id)
    ).all())

    usuarios = db.scalars(select(Usuario).order_by(Usuario.papel, Usuario.email)).all()
    linhas = [
        f"# Auditoria de permissões — {agora:%Y-%m-%d %H:%M} UTC",
        "",
        f"Janela de inatividade: {dias_inativo} dias. Usuários: {len(usuarios)}.",
        "",
        "| Usuário | Papel | Último login | Sessões ativas | 403 no período | Situação |",
        "|---|---|---|---|---|---|",
    ]
    admins = 0
    for u in usuarios:
        admins += u.papel.value == "admin"
        visto = ultimo_login.get(u.id)
        situacao = []
        if visto is None or visto < corte:
            situacao.append("inativo: revisar/desativar")
        if negados.get(u.id, 0) > 0:
            situacao.append("tentou acesso fora do papel")
        linhas.append(
            f"| {u.email} | {u.papel.value} | {visto:%Y-%m-%d} |" if visto else f"| {u.email} | {u.papel.value} | nunca |"
        )
        linhas[-1] += f" {sessoes.get(u.id, 0)} | {negados.get(u.id, 0)} | {'; '.join(situacao) or 'ok'} |"
        if situacao:
            pendencias.append(f"{u.email}: {'; '.join(situacao)}")

    if admins > MAX_ADMINS:
        pendencias.append(f"{admins} administradores (limite da politica: {MAX_ADMINS})")
    linhas += ["", f"Administradores: {admins} (limite {MAX_ADMINS}).", "", "## Pendências", ""]
    linhas += [f"- {p}" for p in pendencias] or ["- nenhuma"]
    return "\n".join(linhas) + "\n", pendencias


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dias-inativo", type=int, default=90)
    ap.add_argument("--saida", default="")
    a = ap.parse_args()
    with SessionLocal() as db:
        relatorio, pendencias = gerar(db, a.dias_inativo)
    if a.saida:
        with open(a.saida, "w", encoding="utf-8") as f:
            f.write(relatorio)
    print(relatorio)
    return 1 if pendencias else 0


if __name__ == "__main__":
    raise SystemExit(main())
