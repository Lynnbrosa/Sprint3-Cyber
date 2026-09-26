import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, String, Text
from sqlalchemy.dialects.postgresql import UUID

from app.db.session import Base


class AuditAction(str, enum.Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGIN_LOCKED = "LOGIN_LOCKED"
    LOGOUT = "LOGOUT"
    TOKEN_REFRESHED = "TOKEN_REFRESHED"
    CLIENTE_CREATED = "CLIENTE_CREATED"
    CLIENTE_ANONYMIZED = "CLIENTE_ANONYMIZED"
    LEAD_CREATED = "LEAD_CREATED"
    LEAD_PATCHED = "LEAD_PATCHED"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    FORBIDDEN_ACCESS = "FORBIDDEN_ACCESS"
    SIGNATURE_REJECTED = "SIGNATURE_REJECTED"
    MASS_QUERY_DETECTED = "MASS_QUERY_DETECTED"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action = Column(
        Enum(AuditAction, name="audit_action", values_callable=lambda x: [e.value for e in x]),
        nullable=False, index=True,
    )
    actor_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    actor_email = Column(String(180), nullable=True)
    actor_role = Column(String(20), nullable=True)
    entity_type = Column(String(40), nullable=True)
    entity_id = Column(String(64), nullable=True)
    request_id = Column(String(64), nullable=True, index=True)
    remote_ip = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    details = Column(Text, nullable=True)
    occurred_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
