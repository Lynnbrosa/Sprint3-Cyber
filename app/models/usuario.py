import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, String
from sqlalchemy.dialects.postgresql import UUID

from app.db.session import Base


class RolePapel(str, enum.Enum):
    CONSULTOR = "consultor"
    ADMIN = "admin"
    ANALISTA = "analista"


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(120), nullable=False)
    email = Column(String(180), unique=True, nullable=False, index=True)
    senha_hash = Column(String(255), nullable=False)
    papel = Column(Enum(RolePapel, name="role_papel", values_callable=lambda x: [e.value for e in x]),
                   nullable=False, default=RolePapel.CONSULTOR)
    criado_em = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
