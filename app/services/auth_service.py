from datetime import datetime, timezone
from uuid import UUID

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import UnauthorizedError
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    Principal,
    Role,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.models import AuditAction, RefreshToken, RevokedToken, Usuario
from app.schemas.auth import TokenPair
from app.services.alert_service import maybe_alert_login_brute_force, notify_webhook
from app.services.audit_service import AuditService
from app.services.lockout_service import LockoutService


def normalize_email(email: str) -> str:
    return email.strip().lower()


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)
        self.lockout = LockoutService(db)
        self._settings = get_settings()

    def login(self, email: str, senha: str, request: Request) -> TokenPair:
        # sem normalizar, "Admin@Ford.com" e "admin@ford.com" contavam lockout separado
        email = normalize_email(email)

        if self.lockout.is_locked(email):
            self.audit.log_event(action=AuditAction.LOGIN_LOCKED, request=request, actor_email=email)
            # quem levanta excecao nao passa pelo db.commit() da rota, a trilha sumia no rollback
            self.db.commit()
            raise UnauthorizedError("Conta temporariamente bloqueada. Tente novamente em alguns minutos.")

        usuario = self.db.scalar(select(Usuario).where(Usuario.email == email))
        # usuario inexistente tambem paga o bcrypt, senao o tempo de resposta entrega quem existe
        ok = verify_password(senha, usuario.senha_hash if usuario else DUMMY_PASSWORD_HASH) and usuario is not None

        self.lockout.record(email, success=ok, request=request)

        if not ok:
            self.audit.log_event(
                action=AuditAction.LOGIN_FAILED,
                request=request,
                actor_email=email,
                details="usuario_inexistente" if usuario is None else "senha_invalida",
            )
            maybe_alert_login_brute_force(email, self.audit, request)
            # mesmo motivo do lockout: sem commit a falha nunca contava pro bloqueio
            self.db.commit()
            raise UnauthorizedError("Credenciais inválidas")

        role = Role(usuario.papel.value)
        access_token, _ = create_access_token(subject=str(usuario.id), role=role, nome=usuario.nome)
        refresh_token, jti, exp = create_refresh_token(subject=str(usuario.id), role=role)
        self.db.add(RefreshToken(jti=jti, usuario_id=usuario.id, expires_at=exp))

        self.audit.log_event(
            action=AuditAction.LOGIN_SUCCESS,
            request=request,
            actor_id=usuario.id,
            actor_email=usuario.email,
            actor_role=role.value,
            entity_type="Usuario",
            entity_id=str(usuario.id),
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_in=self._settings.jwt_access_ttl_minutes * 60,
            refresh_expires_in=self._settings.jwt_refresh_ttl_days * 86400,
            role=usuario.papel,
        )

    def refresh(self, refresh_token: str, request: Request) -> TokenPair:
        payload = decode_token(refresh_token, expected_type=TokenType.REFRESH)
        jti = payload["jti"]

        stored = self.db.scalar(select(RefreshToken).where(RefreshToken.jti == jti))
        if stored is not None and stored.revoked:
            # refresh ja rotacionado voltando = alguem tem copia do token (o dono ou o ladrao).
            # nao da pra saber qual, entao derruba a familia inteira (OAuth 2.0 BCP, reuse detection)
            revogados = self.revoke_all_sessions(stored.usuario_id)
            self.audit.log_event(
                action=AuditAction.REFRESH_REUSE_DETECTED,
                request=request,
                actor_id=stored.usuario_id,
                entity_type="Usuario",
                entity_id=str(stored.usuario_id),
                details=f"refresh reutilizado; {revogados} sessoes revogadas",
            )
            self.db.commit()
            notify_webhook({"type": "refresh_reuse", "usuario_id": str(stored.usuario_id)})
            raise UnauthorizedError("Refresh token inválido ou revogado")

        if stored is None or stored.expires_at <= datetime.now(timezone.utc):
            self.audit.log_event(
                action=AuditAction.UNAUTHORIZED_ACCESS,
                request=request,
                details="refresh_token_invalid_or_revoked",
            )
            self.db.commit()
            raise UnauthorizedError("Refresh token inválido ou revogado")

        # Rotação: revoga o token usado, emite par novo.
        stored.revoked = True
        usuario = self.db.get(Usuario, stored.usuario_id)
        if usuario is None:
            raise UnauthorizedError("Usuário não encontrado")

        role = Role(usuario.papel.value)
        access_token, _ = create_access_token(subject=str(usuario.id), role=role, nome=usuario.nome)
        new_refresh, new_jti, exp = create_refresh_token(subject=str(usuario.id), role=role)
        self.db.add(RefreshToken(jti=new_jti, usuario_id=usuario.id, expires_at=exp))

        self.audit.log_event(
            action=AuditAction.TOKEN_REFRESHED,
            request=request,
            actor_id=usuario.id,
            actor_email=usuario.email,
            actor_role=role.value,
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=new_refresh,
            access_expires_in=self._settings.jwt_access_ttl_minutes * 60,
            refresh_expires_in=self._settings.jwt_refresh_ttl_days * 86400,
            role=usuario.papel,
        )

    def logout(self, refresh_token: str, principal: Principal, request: Request) -> None:
        # o access continuava valendo ate o exp depois do logout; agora o jti vai pra denylist
        exp = datetime.fromtimestamp(principal.exp, tz=timezone.utc) if principal.exp else datetime.now(timezone.utc)
        if self.db.get(RevokedToken, principal.jti) is None:
            self.db.add(RevokedToken(jti=principal.jti, expires_at=exp, motivo="logout"))

        try:
            payload = decode_token(refresh_token, expected_type=TokenType.REFRESH)
            stored = self.db.scalar(select(RefreshToken).where(RefreshToken.jti == payload["jti"]))
            # so revoga refresh do proprio usuario, senao dava pra deslogar os outros
            if stored and not stored.revoked and str(stored.usuario_id) == principal.user_id:
                stored.revoked = True
        except Exception:  # nosec B110 - logout best-effort: refresh invalido tambem resulta em "logado fora"
            pass
        self.audit.log_event(action=AuditAction.LOGOUT, request=request)

    def revoke_all_sessions(self, usuario_id: UUID) -> int:
        """Kill switch da contencao: revoga todos os refresh e invalida todo access emitido ate agora."""
        result = self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.usuario_id == usuario_id, RefreshToken.revoked.is_(False))
            .values(revoked=True)
        )
        usuario = self.db.get(Usuario, usuario_id)
        if usuario is not None:
            usuario.sessoes_revogadas_em = datetime.now(timezone.utc)
        return result.rowcount or 0
