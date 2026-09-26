from sqlalchemy import Column, DateTime, String

from app.db.session import Base


class HmacNonce(Base):
    """Assinatura HMAC ja aceita. A PK impede o mesmo POST assinado de passar duas vezes."""
    __tablename__ = "hmac_nonces"

    signature = Column(String(64), primary_key=True)
    seen_at = Column(DateTime(timezone=True), nullable=False, index=True)
