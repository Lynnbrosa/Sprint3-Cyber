from uuid import UUID

from fastapi import Request
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, joinedload

from app.core.errors import NotFoundError
from app.models import AuditAction, Lead, PrioridadeLead, StatusLead
from app.schemas.lead import (
    LeadDetail,
    LeadListItem,
    LeadListResponse,
    LeadPatchRequest,
)
from app.services.alert_service import maybe_alert_mass_query
from app.services.audit_service import AuditService
from app.services.cliente_service import cliente_to_output, veiculo_to_output


_PRIORIDADE_ORDER = case(
    {
        PrioridadeLead.CRITICA: 0,
        PrioridadeLead.ALTA: 1,
        PrioridadeLead.MEDIA: 2,
        PrioridadeLead.BAIXA: 3,
    },
    value=Lead.prioridade,
)


class LeadService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)

    def listar(
        self,
        *,
        prioridade: PrioridadeLead | None,
        status: StatusLead | None,
        page: int,
        per_page: int,
        request: Request,
        principal_id: str | None,
    ) -> LeadListResponse:
        maybe_alert_mass_query(principal_id, self.audit, request)

        base = select(Lead).options(joinedload(Lead.cliente), joinedload(Lead.veiculo))
        if prioridade is not None:
            base = base.where(Lead.prioridade == prioridade)
        if status is not None:
            base = base.where(Lead.status == status)

        total = self.db.scalar(
            select(func.count()).select_from(base.subquery())
        ) or 0

        items = self.db.scalars(
            base.order_by(_PRIORIDADE_ORDER.asc(), Lead.score_risco.desc(), Lead.criado_em.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
        ).all()

        return LeadListResponse(
            items=[
                LeadListItem(
                    id=l.id,
                    cliente_id=l.cliente_id,
                    veiculo_id=l.veiculo_id,
                    nome_cliente=l.cliente.nome,
                    modelo_veiculo=f"{l.veiculo.modelo} {l.veiculo.versao}",
                    score_risco=l.score_risco,
                    prioridade=l.prioridade,
                    status=l.status,
                    criado_em=l.criado_em,
                )
                for l in items
            ],
            page=page,
            per_page=per_page,
            total=total,
        )

    def obter(self, lead_id: UUID) -> LeadDetail:
        lead = self.db.scalar(
            select(Lead)
            .where(Lead.id == lead_id)
            .options(joinedload(Lead.cliente), joinedload(Lead.veiculo))
        )
        if lead is None:
            raise NotFoundError("Lead não encontrado")
        return LeadDetail(
            id=lead.id,
            score_risco=lead.score_risco,
            prioridade=lead.prioridade,
            status=lead.status,
            script_oferta=lead.script_oferta,
            observacao=lead.observacao,
            criado_em=lead.criado_em,
            atualizado_em=lead.atualizado_em,
            cliente=cliente_to_output(lead.cliente),
            veiculo=veiculo_to_output(lead.veiculo),
        )

    def atualizar_status(self, lead_id: UUID, patch: LeadPatchRequest, request: Request) -> LeadDetail:
        lead = self.db.scalar(
            select(Lead)
            .where(Lead.id == lead_id)
            .options(joinedload(Lead.cliente), joinedload(Lead.veiculo))
        )
        if lead is None:
            raise NotFoundError("Lead não encontrado")

        old_status = lead.status
        lead.status = patch.status
        if patch.observacao is not None:
            # Sanitização: bloqueia caracteres de controle (XSS é mitigado no front, mas defense in depth).
            cleaned = "".join(ch for ch in patch.observacao if ch.isprintable() or ch in ("\n", "\r", "\t"))
            lead.observacao = cleaned

        self.audit.log_event(
            action=AuditAction.LEAD_PATCHED,
            request=request,
            entity_type="Lead",
            entity_id=str(lead.id),
            details=f"status: {old_status.value} -> {patch.status.value}",
        )

        return LeadDetail(
            id=lead.id,
            score_risco=lead.score_risco,
            prioridade=lead.prioridade,
            status=lead.status,
            script_oferta=lead.script_oferta,
            observacao=lead.observacao,
            criado_em=lead.criado_em,
            atualizado_em=lead.atualizado_em,
            cliente=cliente_to_output(lead.cliente),
            veiculo=veiculo_to_output(lead.veiculo),
        )
