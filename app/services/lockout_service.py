from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import LoginAttempt
from app.services.audit_service import client_ip


class LockoutService:
    """
    Bloqueia o email quando acontecem LOCKOUT_MAX_FAILURES falhas dentro de
    LOCKOUT_WINDOW_SECONDS; o bloqueio dura LOCKOUT_DURATION_SECONDS a partir
    da última falha. Um login bem-sucedido zera a contagem.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self._settings = get_settings()

    def _last_success_at(self, email: str) -> datetime | None:
        return self.db.scalar(
            select(LoginAttempt.attempted_at)
            .where(LoginAttempt.email == email, LoginAttempt.success.is_(True))
            .order_by(LoginAttempt.attempted_at.desc())
            .limit(1)
        )

    def is_locked(self, email: str) -> bool:
        s = self._settings
        now = datetime.now(timezone.utc)
        since = now - timedelta(seconds=s.lockout_duration_seconds + s.lockout_window_seconds)
        last_ok = self._last_success_at(email)
        if last_ok is not None and last_ok > since:
            since = last_ok

        falhas = self.db.scalars(
            select(LoginAttempt.attempted_at)
            .where(
                LoginAttempt.email == email,
                LoginAttempt.success.is_(False),
                LoginAttempt.attempted_at > since,
            )
            .order_by(LoginAttempt.attempted_at.desc())
            .limit(s.lockout_max_failures)
        ).all()
        if len(falhas) < s.lockout_max_failures:
            return False

        mais_nova, mais_antiga = falhas[0], falhas[-1]
        dentro_da_janela = (mais_nova - mais_antiga).total_seconds() <= s.lockout_window_seconds
        ainda_bloqueado = (now - mais_nova).total_seconds() < s.lockout_duration_seconds
        return dentro_da_janela and ainda_bloqueado

    def recent_failure_count(self, email: str, window_seconds: int) -> int:
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        return len(self.db.scalars(
            select(LoginAttempt.id).where(
                LoginAttempt.email == email,
                LoginAttempt.success.is_(False),
                LoginAttempt.attempted_at >= since,
            )
        ).all())

    def record(self, email: str, success: bool, request: Request | None = None) -> None:
        attempt = LoginAttempt(
            email=email,
            success=success,
            remote_ip=client_ip(request),
            attempted_at=datetime.now(timezone.utc),
        )
        self.db.add(attempt)
        self.db.flush()
