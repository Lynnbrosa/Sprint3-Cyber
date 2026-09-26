"""
Verificação de assinatura HMAC-SHA256 em payloads críticos.

Cliente envia: X-Signature: <hex>  e  X-Timestamp: <unix-seconds>
Server: recompõe HMAC sobre `f"{timestamp}.{body_bytes}"` e compara em constant time.

Janela de tempo (default 5 min) impede replay de requisições antigas.
"""
from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Header, HTTPException, Request, status

from app.core.config import get_settings


SIGNATURE_HEADER = "X-Signature"
TIMESTAMP_HEADER = "X-Timestamp"
MAX_SKEW_SECONDS = 300  # 5 min


async def require_hmac_signature(
    request: Request,
    x_signature: str | None = Header(default=None, alias=SIGNATURE_HEADER),
    x_timestamp: str | None = Header(default=None, alias=TIMESTAMP_HEADER),
) -> None:
    if not x_signature or not x_timestamp:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_SIGNATURE", "message": "X-Signature e X-Timestamp obrigatórios"},
        )

    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_SIGNATURE", "message": "X-Timestamp inválido"},
        )

    if abs(time.time() - ts) > MAX_SKEW_SECONDS:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_SIGNATURE", "message": "X-Timestamp fora da janela permitida"},
        )

    body = await request.body()
    settings = get_settings()
    mac = hmac.new(
        settings.hmac_payload_secret.encode("utf-8"),
        f"{ts}.".encode("utf-8") + body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(mac, x_signature.lower()):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_SIGNATURE", "message": "Assinatura inválida"},
        )
