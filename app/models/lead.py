import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class PrioridadeLead(str, enum.Enum):
    CRITICA = "critica"
    ALTA = "alta"
    MEDIA = "media"
    BAIXA = "baixa"


class StatusLead(str, enum.Enum):
    ABERTO = "aberto"
    AGENDADO = "agendado"
    RECUSADO = "recusado"
    SEM_CONTATO = "sem-contato"


class Lead(Base):
    __tablename__ = "leads"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cliente_id = Column(UUID(as_uuid=True), ForeignKey("clientes.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    veiculo_id = Column(UUID(as_uuid=True), ForeignKey("veiculos.id", ondelete="CASCADE"),
                        nullable=False, index=True)

    score_risco = Column(Float, nullable=False)
    prioridade = Column(
        Enum(PrioridadeLead, name="prioridade_lead", values_callable=lambda x: [e.value for e in x]),
        nullable=False, index=True,
    )
    status = Column(
        Enum(StatusLead, name="status_lead", values_callable=lambda x: [e.value for e in x]),
        nullable=False, default=StatusLead.ABERTO, index=True,
    )
    script_oferta = Column(Text, nullable=True)
    observacao = Column(Text, nullable=True)
    criado_em = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    atualizado_em = Column(DateTime(timezone=True), default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    cliente = relationship("Cliente", back_populates="leads")
    veiculo = relationship("Veiculo", back_populates="leads")
