"""telemetria de veiculos conectados (MQTT)

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "telemetria",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("vin", sa.String(17), nullable=False),
        sa.Column("medido_em", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recebido_em", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("odometro_km", sa.Integer, nullable=False),
        sa.Column("velocidade_kmh", sa.Integer, nullable=True),
        sa.Column("combustivel_pct", sa.Integer, nullable=True),
        sa.Column("codigos_falha", sa.String(120), nullable=True),
        sa.Column("lat_aprox", sa.Float, nullable=True),
        sa.Column("lon_aprox", sa.Float, nullable=True),
        sa.CheckConstraint("odometro_km >= 0", name="ck_telemetria_odometro"),
    )
    op.create_index("ix_telemetria_vin", "telemetria", ["vin"])
    op.create_index("ix_telemetria_recebido_em", "telemetria", ["recebido_em"])
    op.create_index("ix_telemetria_vin_medido_em", "telemetria", ["vin", "medido_em"])


def downgrade() -> None:
    op.drop_table("telemetria")
