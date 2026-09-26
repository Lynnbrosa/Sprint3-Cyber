from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import LoginAttempt


class LockoutService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self._settings = get_settings()

    def is_locked(self, email: str) -> bool:
        since = datetime.now(timezone.utc) - timedelta(seconds=self._settings.lockout_duration_seconds)
        count = self.db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.email == email,
                LoginAttempt.success.is_(False),
                LoginAttempt.attempted_at >= since,
            )
        )
        return (count or 0) >= self._settings.lockout_max_failures

    def recent_failure_count(self, email: str, window_seconds: int) -> int:
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        return self.db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.email == email,
                LoginAttempt.success.is_(False),
                LoginAttempt.attempted_at >= since,
            )
        ) or 0

    def record(self, email: str, success: bool, request: Request | None = None) -> None:
        attempt = LoginAttempt(
            email=email,
            success=success,
            remote_ip=request.client.host if request and request.client else None,
        )
        self.db.add(attempt)
        self.db.flush()
