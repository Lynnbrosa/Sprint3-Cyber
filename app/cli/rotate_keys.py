"""
Recifra a PII de clientes com a chave primaria de FERNET_KEYS.

    FERNET_KEYS="<nova>,<antiga>" python -m app.cli.rotate_keys [--dry-run]

Roda em lotes e commita por lote: se cair no meio, rodar de novo continua de onde
parou (o que ja esta na chave nova so e recifrado de novo, sem perda).
"""
import argparse

from sqlalchemy import select

from app.core.crypto import get_crypto
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.models import AuditAction, Cliente
from app.services.audit_service import AuditService

log = get_logger(__name__)
CAMPOS = ("cpf_encrypted", "email_encrypted", "telefone_encrypted")


def rotacionar(lote: int = 500, dry_run: bool = False) -> int:
    crypto = get_crypto()
    total = 0
    ultimo = None
    with SessionLocal() as db:
        while True:
            q = select(Cliente).order_by(Cliente.id).limit(lote)
            if ultimo is not None:
                q = q.where(Cliente.id > ultimo)
            clientes = db.scalars(q).all()
            if not clientes:
                break
            for c in clientes:
                for campo in CAMPOS:
                    setattr(c, campo, crypto.rotate(getattr(c, campo)))
            total += len(clientes)
            ultimo = clientes[-1].id
            if dry_run:
                db.rollback()
            else:
                db.commit()
        if not dry_run:
            AuditService(db).log_event(action=AuditAction.KEY_ROTATED, entity_type="Cliente",
                                       details=f"{total} registros recifrados")
            db.commit()
    log.info("crypto.rotated", registros=total, dry_run=dry_run)
    return total


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--lote", type=int, default=500)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    print(rotacionar(a.lote, a.dry_run))
