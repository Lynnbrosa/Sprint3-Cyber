from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import Role, requires_role
from app.db.session import get_db
from app.models import AuditAction, AuditLog
from app.schemas.audit import AuditLogItem, AuditLogPage


router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/audit-log", response_model=AuditLogPage)
def list_audit_log(
    action: AuditAction | None = Query(default=None),
    actor_email: str | None = Query(default=None, max_length=180),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _=Depends(requires_role(Role.ADMIN, Role.ANALISTA)),
) -> AuditLogPage:
    base = select(AuditLog)
    if action is not None:
        base = base.where(AuditLog.action == action)
    if actor_email is not None:
        base = base.where(AuditLog.actor_email == actor_email)

    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.scalars(
        base.order_by(AuditLog.occurred_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
    ).all()

    return AuditLogPage(
        items=[
            AuditLogItem(
                id=r.id,
                action=r.action,
                actor_email=r.actor_email,
                actor_role=r.actor_role,
                entity_type=r.entity_type,
                entity_id=r.entity_id,
                request_id=r.request_id,
                remote_ip=r.remote_ip,
                details=r.details,
                occurred_at=r.occurred_at,
            )
            for r in rows
        ],
        page=page,
        per_page=per_page,
        total=total,
    )
