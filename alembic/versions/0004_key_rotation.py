"""acao de auditoria para rotacao de chave de PII

Revision ID: 0004
Revises: 0003
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

ANTES = (
    "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_LOCKED", "LOGOUT", "TOKEN_REFRESHED",
    "CLIENTE_CREATED", "CLIENTE_ANONYMIZED", "LEAD_CREATED", "LEAD_PATCHED",
    "UNAUTHORIZED_ACCESS", "FORBIDDEN_ACCESS", "SIGNATURE_REJECTED", "MASS_QUERY_DETECTED",
    "REFRESH_REUSE_DETECTED", "SESSIONS_REVOKED", "PROFILE_CHANGED",
)
DEPOIS = ANTES + ("KEY_ROTATED",)


def _check(acoes):
    return "action IN (" + ",".join(f"'{a}'" for a in acoes) + ")"


def upgrade() -> None:
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint("ck_audit_action", "audit_logs", _check(DEPOIS))


def downgrade() -> None:
    op.drop_constraint("ck_audit_action", "audit_logs", type_="check")
    op.create_check_constraint("ck_audit_action", "audit_logs", _check(ANTES))
