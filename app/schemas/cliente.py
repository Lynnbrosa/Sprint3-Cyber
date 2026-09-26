import re
from datetime import date, datetime
from decimal import Decimal
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models import PerfilCliente


_CPF_RE = re.compile(r"^\d{11}$")
_VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
_PLACA_RE = re.compile(r"^[A-Z]{3}[0-9][A-Z0-9][0-9]{2}$")


class VeiculoInput(BaseModel):
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}

    modelo: str = Field(..., min_length=1, max_length=80)
    versao: str = Field(..., min_length=1, max_length=80)
    ano: int = Field(..., ge=2000, le=2100)
    vin: str = Field(..., min_length=17, max_length=17)
    placa: Optional[str] = Field(default=None, min_length=7, max_length=8)
    data_compra: date
    valor_compra: Decimal = Field(..., ge=Decimal("0"))
    concessionaria_id: str = Field(..., min_length=1, max_length=40)

    @field_validator("vin")
    @classmethod
    def _vin(cls, v: str) -> str:
        v = v.upper()
        if not _VIN_RE.match(v):
            raise ValueError("VIN inválido (17 alfanuméricos, sem I/O/Q)")
        return v

    @field_validator("placa")
    @classmethod
    def _placa(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.upper().replace("-", "")
        if not _PLACA_RE.match(v):
            raise ValueError("Placa inválida (Mercosul: AAA0A00 ou padrão antigo AAA0000)")
        return v


class VeiculoOutput(BaseModel):
    id: UUID
    modelo: str
    versao: str
    ano: int
    vin: str
    placa: Optional[str] = None
    data_compra: date
    valor_compra: Decimal
    concessionaria_id: str


class ClienteCreate(BaseModel):
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}

    nome: str = Field(..., min_length=2, max_length=180)
    cpf: str = Field(..., min_length=11, max_length=14)
    email: Optional[EmailStr] = Field(default=None, max_length=180)
    telefone: Optional[str] = Field(default=None, max_length=20)
    regiao: str = Field(..., min_length=2, max_length=40)
    veiculo: VeiculoInput

    @field_validator("cpf")
    @classmethod
    def _cpf(cls, v: str) -> str:
        digits = "".join(ch for ch in v if ch.isdigit())
        if not _CPF_RE.match(digits):
            raise ValueError("CPF deve conter 11 dígitos numéricos")
        return digits

    @field_validator("telefone")
    @classmethod
    def _telefone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = re.sub(r"[\s\-()]", "", v)
        if not re.match(r"^\+?\d{10,15}$", cleaned):
            raise ValueError("Telefone inválido (10–15 dígitos, opcional + no início)")
        return cleaned


class ClienteOutput(BaseModel):
    """PII sempre mascarada. Plaintext nunca sai por este DTO."""

    id: UUID
    nome: str
    cpf_masked: str
    email_masked: Optional[str] = None
    telefone_masked: Optional[str] = None
    regiao: str
    perfil: Optional[PerfilCliente] = None
    score_risco: Optional[float] = None
    criado_em: datetime
    classificado_em: Optional[datetime] = None


class ClienteCreatedResponse(BaseModel):
    cliente: ClienteOutput
    lead_id: Optional[UUID] = None
    perfil: PerfilCliente
    score_risco: float
