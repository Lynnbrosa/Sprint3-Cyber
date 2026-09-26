import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, Float, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class PerfilCliente(str, enum.Enum):
    FIEL = "fiel"
    ABANDONO = "abandono"
    ESQUECIDO = "esquecido"
    ECONOMICO = "economico"


class Cliente(Base):
    __tablename__ = "clientes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(180), nullable=False)

    # CPF nunca em texto claro:
    #   - cpf_encrypted: Fernet (não-determinístico, garante confidencialidade)
    #   - cpf_hash: HMAC-SHA256(pepper, cpf) determinístico para lookup
    cpf_encrypted = Column(Text, nullable=False)
    cpf_hash = Column(String(64), unique=True, nullable=False, index=True)

    # Email e telefone também em Fernet (sem lookup determinístico).
    email_encrypted = Column(Text, nullable=True)
    telefone_encrypted = Column(Text, nullable=True)

    regiao = Column(String(40), nullable=False)
    perfil = Column(
        Enum(PerfilCliente, name="perfil_cliente", values_callable=lambda x: [e.value for e in x]),
        nullable=True,
        index=True,
    )
    score_risco = Column(Float, nullable=True)

    criado_em = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    classificado_em = Column(DateTime(timezone=True), nullable=True)

    # LGPD: marcador de anonimização.
    anonimizado_em = Column(DateTime(timezone=True), nullable=True)

    veiculos = relationship("Veiculo", back_populates="cliente", cascade="all, delete-orphan")
    leads = relationship("Lead", back_populates="cliente", cascade="all, delete-orphan")
