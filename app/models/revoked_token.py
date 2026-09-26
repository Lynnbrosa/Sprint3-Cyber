from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String

from app.db.session import Base


class RevokedToken(Base):
    """
    Denylist de access token (jti). O access vive 15 min e é stateless; sem isso,
    quem roubava o token continuava usando depois do logout.
    Linhas expiradas podem ser apagadas: passado o exp o token já é recusado.
    """
    __tablename__ = "revoked_tokens"

    jti = Column(String(64), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    motivo = Column(String(40), nullable=False, default="logout")
