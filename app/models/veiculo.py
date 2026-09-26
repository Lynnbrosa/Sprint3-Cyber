import uuid
from datetime import datetime

from sqlalchemy import Column, Date, DateTime, ForeignKey, Integer, Numeric, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class Veiculo(Base):
    __tablename__ = "veiculos"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cliente_id = Column(UUID(as_uuid=True), ForeignKey("clientes.id", ondelete="CASCADE"),
                        nullable=False, index=True)

    modelo = Column(String(80), nullable=False)
    versao = Column(String(80), nullable=False)
    ano = Column(Integer, nullable=False)
    vin = Column(String(17), unique=True, nullable=False, index=True)
    placa = Column(String(8), nullable=True, index=True)
    data_compra = Column(Date, nullable=False)
    valor_compra = Column(Numeric(12, 2), nullable=False)
    concessionaria_id = Column(String(40), nullable=False, index=True)
    criado_em = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    cliente = relationship("Cliente", back_populates="veiculos")
    leads = relationship("Lead", back_populates="veiculo")
