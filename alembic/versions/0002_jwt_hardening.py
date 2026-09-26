"""denylist de access token, kill switch de sessao e novas acoes de auditoria

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

ACOES_0001 = (
    "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_LOCKED", "LOGOUT", "TOKEN_REFRESHED",
    "CLIENTE_CREATED", "CLIENTE_ANONYMIZED", "LEAD_CREATED", "LEAD_PATCHED",
    "UNAUTHORIZED_ACCESS", "FORBIDDEN_ACCESS", "SIGNATURE_REJECTED", "MASS_QUERY_DETECTED",
)
ACOES_0002 = ACOES_0001 + ("REFRESH_REUSE_DETECTED", "SESSIONS_REVOKED", "PROFILE_CHANGED")


def _check(acoes: tuple[str, ...]) -> str:
    return "action IN (" + ",".join(f"'{a}'" for a in acoes) + ")"


def upgrade() -> None:
    op.create_table(
        "revoked_tokens",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("motivo", sa.String(40), nullable=False, server_default=sa.text("'logout'")),
    )
    op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])

    op.add_column("usuarios", sa.Column("sessoes_revogadas_em", sa.DateTime(timezone=True), nullable=True))

    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint("ck_audit_action", "audit_logs", _check(ACOES_0002))


def downgrade() -> None:
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint("ck_audit_action", "audit_logs", _check(ACOES_0001))
    op.drop_column("usuarios", "sessoes_revogadas_em")
    op.drop_table("revoked_tokens")
