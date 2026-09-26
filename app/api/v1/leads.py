from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.security import Principal, Role, requires_role
from app.db.session import get_db
from app.models import PrioridadeLead, StatusLead
from app.schemas.lead import LeadDetail, LeadListResponse, LeadPatchRequest
from app.services.lead_service import LeadService

router = APIRouter(prefix="/leads", tags=["leads"])


@router.get("", response_model=LeadListResponse)
def listar(
    request: Request,
    prioridade: Optional[PrioridadeLead] = Query(default=None),
    status: Optional[StatusLead] = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    principal: Principal = Depends(requires_role(Role.CONSULTOR, Role.ADMIN, Role.ANALISTA)),
) -> LeadListResponse:
    service = LeadService(db)
    result = service.listar(
        prioridade=prioridade,
        status=status,
        page=page,
        per_page=per_page,
        request=request,
        principal_id=principal.user_id,
    )
    db.commit()
    return result


@router.get("/{lead_id}", response_model=LeadDetail)
def obter(
    lead_id: UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(requires_role(Role.CONSULTOR, Role.ADMIN, Role.ANALISTA)),
) -> LeadDetail:
    return LeadService(db).obter(lead_id)


@router.patch("/{lead_id}", response_model=LeadDetail)
def atualizar(
    lead_id: UUID,
    payload: LeadPatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: Principal = Depends(requires_role(Role.CONSULTOR, Role.ADMIN)),
) -> LeadDetail:
    service = LeadService(db)
    result = service.atualizar_status(lead_id, payload, request)
    db.commit()
    return result
