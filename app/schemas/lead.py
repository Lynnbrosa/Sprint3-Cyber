from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import PrioridadeLead, StatusLead
from app.schemas.cliente import ClienteOutput, VeiculoOutput


class LeadListItem(BaseModel):
    id: UUID
    cliente_id: UUID
    veiculo_id: UUID
    nome_cliente: str
    modelo_veiculo: str
    score_risco: float
    prioridade: PrioridadeLead
    status: StatusLead
    criado_em: datetime


class LeadListResponse(BaseModel):
    items: list[LeadListItem]
    page: int
    per_page: int
    total: int


class LeadDetail(BaseModel):
    id: UUID
    score_risco: float
    prioridade: PrioridadeLead
    status: StatusLead
    script_oferta: Optional[str] = None
    observacao: Optional[str] = None
    criado_em: datetime
    atualizado_em: datetime
    cliente: ClienteOutput
    veiculo: VeiculoOutput


class LeadPatchRequest(BaseModel):
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}

    status: StatusLead
    observacao: Optional[str] = Field(default=None, max_length=2000)
