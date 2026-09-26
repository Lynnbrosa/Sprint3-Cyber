from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from app.models import AuditAction


class AuditLogItem(BaseModel):
    id: UUID
    action: AuditAction
    actor_email: Optional[str] = None
    actor_role: Optional[str] = None
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    request_id: Optional[str] = None
    remote_ip: Optional[str] = None
    details: Optional[str] = None
    occurred_at: datetime


class AuditLogPage(BaseModel):
    items: list[AuditLogItem]
    page: int
    per_page: int
    total: int
