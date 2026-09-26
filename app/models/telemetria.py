import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import UUID

from app.db.session import Base


class Telemetria(Base):
    """
    Leitura de veiculo conectado. Localizacao e dado pessoal (LGPD): so a posicao
    aproximada (2 casas, ~1 km) e guardada, e a tabela tem retencao de 90 dias.
    """
    __tablename__ = "telemetria"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vin = Column(String(17), nullable=False, index=True)
    medido_em = Column(DateTime(timezone=True), nullable=False)
    recebido_em = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    odometro_km = Column(Integer, nullable=False)
    velocidade_kmh = Column(Integer, nullable=True)
    combustivel_pct = Column(Integer, nullable=True)
    codigos_falha = Column(String(120), nullable=True)
    lat_aprox = Column(Float, nullable=True)
    lon_aprox = Column(Float, nullable=True)
