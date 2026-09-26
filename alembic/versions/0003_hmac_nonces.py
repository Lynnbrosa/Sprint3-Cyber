"""assinaturas HMAC ja aceitas (anti-replay dentro da janela)

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hmac_nonces",
        sa.Column("signature", sa.String(64), primary_key=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_hmac_nonces_seen_at", "hmac_nonces", ["seen_at"])


def downgrade() -> None:
    op.drop_table("hmac_nonces")
