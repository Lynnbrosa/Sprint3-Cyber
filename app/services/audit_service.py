from typing import Optional
from uuid import UUID

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models import AuditAction, AuditLog


log = get_logger(__name__)


class AuditService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def log_event(
        self,
        *,
        action: AuditAction,
        request: Optional[Request] = None,
        actor_id: Optional[UUID] = None,
        actor_email: Optional[str] = None,
        actor_role: Optional[str] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        details: Optional[str] = None,
    ) -> AuditLog:
        request_id = None
        remote_ip = None
        user_agent = None
        if request is not None:
            request_id = getattr(request.state, "request_id", None)
            remote_ip = request.client.host if request.client else None
            user_agent = request.headers.get("User-Agent")
            if user_agent and len(user_agent) > 255:
                user_agent = user_agent[:255]
            principal = getattr(request.state, "principal", None)
            if principal and actor_id is None:
                actor_id = UUID(principal.user_id) if principal.user_id else None
                actor_role = principal.role.value
                actor_email = actor_email or principal.nome

        entry = AuditLog(
            action=action,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            entity_type=entity_type,
            entity_id=entity_id,
            request_id=request_id,
            remote_ip=remote_ip,
            user_agent=user_agent,
            details=details,
        )
        self.db.add(entry)
        self.db.flush()

        log.info(
            "audit",
            action=action.value,
            actor_id=str(actor_id) if actor_id else None,
            entity_id=entity_id,
        )
        return entry
