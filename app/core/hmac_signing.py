"""
Verificação de assinatura HMAC-SHA256 em payloads críticos.

Cliente envia: X-Signature: <hex>  e  X-Timestamp: <unix-seconds>
Server: recompõe HMAC sobre `f"{timestamp}.{body_bytes}"` e compara em constant time.

A janela de 5 min barra requisição velha; dentro da janela cada assinatura
só vale uma vez (tabela hmac_nonces), senão quem capturasse um POST de
faturamento podia reenviar o mesmo cadastro quantas vezes quisesse.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import get_db


log = get_logger(__name__)

SIGNATURE_HEADER = "X-Signature"
TIMESTAMP_HEADER = "X-Timestamp"
MAX_SKEW_SECONDS = 300  # 5 min


def _rejeitar(db: Session, request: Request, motivo: str, mensagem: str) -> HTTPException:
    from app.models import AuditAction
    from app.services.audit_service import AuditService

    try:
        AuditService(db).log_event(action=AuditAction.SIGNATURE_REJECTED, request=request, details=motivo)
        db.commit()
    except Exception:  # auditoria nao pode virar 500 aqui
        db.rollback()
        log.warning("audit.signature_rejected_failed", motivo=motivo)
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail={"code": "INVALID_SIGNATURE", "message": mensagem},
    )


def assinar(body: bytes, ts: int, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), f"{ts}.".encode("utf-8") + body, hashlib.sha256).hexdigest()


async def require_hmac_signature(
    request: Request,
    x_signature: str | None = Header(default=None, alias=SIGNATURE_HEADER),
    x_timestamp: str | None = Header(default=None, alias=TIMESTAMP_HEADER),
    db: Session = Depends(get_db),
) -> None:
    if not x_signature or not x_timestamp:
        raise _rejeitar(db, request, "headers_ausentes", "X-Signature e X-Timestamp obrigatórios")

    try:
        ts = int(x_timestamp)
    except ValueError:
        raise _rejeitar(db, request, "timestamp_invalido", "X-Timestamp inválido") from None

    if abs(time.time() - ts) > MAX_SKEW_SECONDS:
        raise _rejeitar(db, request, "fora_da_janela", "X-Timestamp fora da janela permitida")

    body = await request.body()
    mac = assinar(body, ts, get_settings().hmac_payload_secret)
    if not hmac.compare_digest(mac, x_signature.lower()):
        raise _rejeitar(db, request, "assinatura_invalida", "Assinatura inválida")

    from app.models import HmacNonce

    agora = datetime.now(timezone.utc)
    db.execute(delete(HmacNonce).where(HmacNonce.seen_at < agora - timedelta(seconds=2 * MAX_SKEW_SECONDS)))
    db.add(HmacNonce(signature=mac, seen_at=agora))
    try:
        # commit ja aqui: dois replays em paralelo batem na PK e so um passa
        db.commit()
    except IntegrityError:
        db.rollback()
        raise _rejeitar(db, request, "replay", "Requisição já processada (replay)") from None
