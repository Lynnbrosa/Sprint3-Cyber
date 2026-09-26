"""
Detector de anomalias e disparador de alertas de segurança.

Triggers:
- 5 falhas de login no mesmo email em 1 minuto.
- Consulta massiva: > N leads por minuto pelo mesmo principal.
- Alteração de perfil de cliente (qualquer escrita no campo perfil).
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Optional

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import AuditAction
from app.services.audit_service import AuditService


log = get_logger(__name__)


class _SlidingCounter:
    """Contador thread-safe com janela deslizante por chave (em memória)."""

    def __init__(self, window_seconds: float) -> None:
        self.window = window_seconds
        self._timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def hit(self, key: str) -> int:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            dq = self._timestamps[key]
            dq.append(now)
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)


# Singletons em memória (substituir por Redis em ambiente multi-réplica).
_login_failures = _SlidingCounter(window_seconds=60)
_query_counter = _SlidingCounter(window_seconds=60)
MASS_QUERY_THRESHOLD = 100


def notify_webhook(payload: dict) -> None:
    url = get_settings().security_alert_webhook_url
    if not url:
        return
    try:
        httpx.post(url, json=payload, timeout=2.0)
    except Exception as e:
        log.warning("alert_webhook_failed", error=str(e))


def maybe_alert_login_brute_force(email: str, audit: AuditService, request) -> None:
    count = _login_failures.hit(email)
    if count >= 5:
        log.warning("alert.login_brute_force", email=email, count_1m=count)
        audit.log_event(
            action=AuditAction.LOGIN_LOCKED,
            request=request,
            actor_email=email,
            details=f"5+ falhas em 60s (count={count})",
        )
        notify_webhook({"type": "login_brute_force", "email": email, "count_1m": count})


def maybe_alert_mass_query(principal_id: Optional[str], audit: AuditService, request) -> None:
    if not principal_id:
        return
    count = _query_counter.hit(principal_id)
    if count == MASS_QUERY_THRESHOLD + 1:
        log.warning("alert.mass_query", actor=principal_id, count_1m=count)
        audit.log_event(
            action=AuditAction.MASS_QUERY_DETECTED,
            request=request,
            details=f"{count} leituras em 60s",
        )
        notify_webhook({"type": "mass_query", "actor": principal_id, "count_1m": count})


def alert_profile_change(cliente_id: str, old_perfil: str | None, new_perfil: str, audit: AuditService, request) -> None:
    log.warning("alert.profile_change", cliente_id=cliente_id, old=old_perfil, new=new_perfil)
    audit.log_event(
        action=AuditAction.CLIENTE_CREATED,  # ou um novo PROFILE_CHANGED se preferir
        request=request,
        entity_type="Cliente",
        entity_id=cliente_id,
        details=f"perfil: {old_perfil} -> {new_perfil}",
    )
    notify_webhook({"type": "profile_change", "cliente_id": cliente_id, "old": old_perfil, "new": new_perfil})
