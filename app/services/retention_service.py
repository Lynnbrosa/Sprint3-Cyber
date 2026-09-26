"""
Política de retenção LGPD.

Após N anos da criação (default 5), o registro é ANONIMIZADO de forma
IRREVERSÍVEL:
- CPF, email, telefone, nome → substituídos por tokens pseudonimizados.
- Indicadores estatísticos (perfil, score) são MANTIDOS para análises agregadas.

Esse processo é one-way: nem o operador (sistema) nem o controlador (Ford)
conseguem reverter — atende ao princípio de necessidade da LGPD Art. 16.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.crypto import get_crypto, pseudonymize
from app.core.logging import get_logger
from app.models import AuditAction, Cliente
from app.services.audit_service import AuditService


log = get_logger(__name__)


def anonymize_expired(db: Session, dry_run: bool = False) -> int:
    settings = get_settings()
    crypto = get_crypto()
    audit = AuditService(db)

    cutoff = datetime.now(timezone.utc) - timedelta(days=365 * settings.retention_years)
    expired = db.scalars(
        select(Cliente).where(
            Cliente.criado_em < cutoff,
            Cliente.anonimizado_em.is_(None),
        )
    ).all()

    if not expired:
        log.info("retention.nothing_to_anonymize", cutoff=cutoff.isoformat())
        return 0

    count = 0
    for c in expired:
        pseudo = pseudonymize(str(c.id))
        if not dry_run:
            c.nome = f"ANONIMIZADO_{pseudo[-8:]}"
            c.cpf_encrypted = crypto.encrypt(pseudo)
            c.cpf_hash = pseudo  # irreversível — sobrescreve o hash original
            c.email_encrypted = None
            c.telefone_encrypted = None
            c.anonimizado_em = datetime.now(timezone.utc)
            audit.log_event(
                action=AuditAction.CLIENTE_ANONYMIZED,
                entity_type="Cliente",
                entity_id=str(c.id),
                details=f"retencao_expired cutoff={cutoff.isoformat()}",
            )
        count += 1

    log.info("retention.anonymized", count=count, dry_run=dry_run, cutoff=cutoff.isoformat())
    if not dry_run:
        db.commit()
    return count
