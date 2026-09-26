"""initial schema with security hardening built-in

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.create_table(
        "usuarios",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("nome", sa.String(120), nullable=False),
        sa.Column("email", sa.String(180), nullable=False, unique=True),
        sa.Column("senha_hash", sa.String(255), nullable=False),
        sa.Column("papel", sa.String(20), nullable=False),
        sa.Column("criado_em", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint("papel IN ('consultor','admin','analista')", name="ck_usuarios_papel"),
    )
    op.create_index("ix_usuarios_email", "usuarios", ["email"])

    op.create_table(
        "clientes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("nome", sa.String(180), nullable=False),
        sa.Column("cpf_encrypted", sa.Text, nullable=False),
        sa.Column("cpf_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("email_encrypted", sa.Text, nullable=True),
        sa.Column("telefone_encrypted", sa.Text, nullable=True),
        sa.Column("regiao", sa.String(40), nullable=False),
        sa.Column("perfil", sa.String(20), nullable=True),
        sa.Column("score_risco", sa.Float, nullable=True),
        sa.Column("criado_em", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("classificado_em", sa.DateTime(timezone=True), nullable=True),
        sa.Column("anonimizado_em", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("perfil IS NULL OR perfil IN ('fiel','abandono','esquecido','economico')",
                           name="ck_clientes_perfil"),
    )
    op.create_index("ix_clientes_cpf_hash", "clientes", ["cpf_hash"], unique=True)
    op.create_index("ix_clientes_perfil", "clientes", ["perfil"])
    op.create_index("ix_clientes_criado_em", "clientes", ["criado_em"])

    op.create_table(
        "veiculos",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cliente_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("modelo", sa.String(80), nullable=False),
        sa.Column("versao", sa.String(80), nullable=False),
        sa.Column("ano", sa.Integer, nullable=False),
        sa.Column("vin", sa.String(17), nullable=False, unique=True),
        sa.Column("placa", sa.String(8), nullable=True),
        sa.Column("data_compra", sa.Date, nullable=False),
        sa.Column("valor_compra", sa.Numeric(12, 2), nullable=False),
        sa.Column("concessionaria_id", sa.String(40), nullable=False),
        sa.Column("criado_em", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("ix_veiculos_cliente_id", "veiculos", ["cliente_id"])
    op.create_index("ix_veiculos_vin", "veiculos", ["vin"])
    op.create_index("ix_veiculos_placa", "veiculos", ["placa"])
    op.create_index("ix_veiculos_concessionaria_id", "veiculos", ["concessionaria_id"])

    op.create_table(
        "leads",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cliente_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("veiculo_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("veiculos.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score_risco", sa.Float, nullable=False),
        sa.Column("prioridade", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'aberto'")),
        sa.Column("script_oferta", sa.Text, nullable=True),
        sa.Column("observacao", sa.Text, nullable=True),
        sa.Column("criado_em", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("atualizado_em", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint("prioridade IN ('critica','alta','media','baixa')", name="ck_leads_prioridade"),
        sa.CheckConstraint("status IN ('aberto','agendado','recusado','sem-contato')", name="ck_leads_status"),
    )
    op.create_index("ix_leads_cliente_id", "leads", ["cliente_id"])
    op.create_index("ix_leads_veiculo_id", "leads", ["veiculo_id"])
    op.create_index("ix_leads_prioridade", "leads", ["prioridade"])
    op.create_index("ix_leads_status", "leads", ["status"])
    op.create_index("ix_leads_prioridade_status", "leads", ["prioridade", "status"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("jti", sa.String(64), nullable=False, unique=True),
        sa.Column("usuario_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.text("false")),
    )
    op.create_index("ix_refresh_tokens_jti", "refresh_tokens", ["jti"], unique=True)
    op.create_index("ix_refresh_tokens_usuario_id", "refresh_tokens", ["usuario_id"])
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"])
    op.create_index("ix_refresh_tokens_revoked", "refresh_tokens", ["revoked"])

    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_email", sa.String(180), nullable=True),
        sa.Column("actor_role", sa.String(20), nullable=True),
        sa.Column("entity_type", sa.String(40), nullable=True),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("remote_ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.Column("details", sa.Text, nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint(
            "action IN ('LOGIN_SUCCESS','LOGIN_FAILED','LOGIN_LOCKED','LOGOUT',"
            "'TOKEN_REFRESHED','CLIENTE_CREATED','CLIENTE_ANONYMIZED',"
            "'LEAD_CREATED','LEAD_PATCHED','UNAUTHORIZED_ACCESS','FORBIDDEN_ACCESS',"
            "'SIGNATURE_REJECTED','MASS_QUERY_DETECTED')",
            name="ck_audit_action",
        ),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])
    op.create_index("ix_audit_logs_occurred_at", "audit_logs", ["occurred_at"])
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"])

    op.create_table(
        "login_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(180), nullable=False),
        sa.Column("success", sa.Boolean, nullable=False),
        sa.Column("remote_ip", sa.String(64), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("ix_login_attempts_email", "login_attempts", ["email"])
    op.create_index("ix_login_attempts_attempted_at", "login_attempts", ["attempted_at"])
    op.create_index("ix_login_attempts_email_at", "login_attempts", ["email", "attempted_at"])


def downgrade() -> None:
    op.drop_table("login_attempts")
    op.drop_table("audit_logs")
    op.drop_table("refresh_tokens")
    op.drop_table("leads")
    op.drop_table("veiculos")
    op.drop_table("clientes")
    op.drop_table("usuarios")
