from typing import Optional
from uuid import UUID

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import get_crypto, mask_cpf, mask_email, mask_telefone
from app.core.errors import ConflictError
from app.models import AuditAction, Cliente, Lead, StatusLead, Veiculo
from app.schemas.cliente import (
    ClienteCreate,
    ClienteCreatedResponse,
    ClienteOutput,
    VeiculoOutput,
)
from app.services import ml_service
from app.services.audit_service import AuditService


def cliente_to_output(c: Cliente, crypto=None) -> ClienteOutput:
    crypto = crypto or get_crypto()
    cpf_plain = crypto.decrypt(c.cpf_encrypted)
    email_plain = crypto.decrypt(c.email_encrypted)
    telefone_plain = crypto.decrypt(c.telefone_encrypted)
    return ClienteOutput(
        id=c.id,
        nome=c.nome,
        cpf_masked=mask_cpf(cpf_plain) or "",
        email_masked=mask_email(email_plain),
        telefone_masked=mask_telefone(telefone_plain),
        regiao=c.regiao,
        perfil=c.perfil,
        score_risco=c.score_risco,
        criado_em=c.criado_em,
        classificado_em=c.classificado_em,
    )


def veiculo_to_output(v: Veiculo) -> VeiculoOutput:
    return VeiculoOutput(
        id=v.id,
        modelo=v.modelo,
        versao=v.versao,
        ano=v.ano,
        vin=v.vin,
        placa=v.placa,
        data_compra=v.data_compra,
        valor_compra=v.valor_compra,
        concessionaria_id=v.concessionaria_id,
    )


class ClienteService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.crypto = get_crypto()
        self.audit = AuditService(db)

    def cadastrar_compra(self, payload: ClienteCreate, request: Request) -> ClienteCreatedResponse:
        cpf_hash = self.crypto.cpf_hash(payload.cpf)
        existing = self.db.scalar(select(Cliente).where(Cliente.cpf_hash == cpf_hash))
        if existing is not None:
            raise ConflictError("Cliente já cadastrado", details={"cpf": "duplicado"})

        existing_vin = self.db.scalar(select(Veiculo).where(Veiculo.vin == payload.veiculo.vin))
        if existing_vin is not None:
            raise ConflictError("Veículo já cadastrado", details={"vin": payload.veiculo.vin})

        cliente = Cliente(
            nome=payload.nome,
            cpf_encrypted=self.crypto.encrypt(payload.cpf),
            cpf_hash=cpf_hash,
            email_encrypted=self.crypto.encrypt(payload.email),
            telefone_encrypted=self.crypto.encrypt(payload.telefone),
            regiao=payload.regiao,
        )
        self.db.add(cliente)
        self.db.flush()

        veiculo = Veiculo(
            cliente_id=cliente.id,
            modelo=payload.veiculo.modelo,
            versao=payload.veiculo.versao,
            ano=payload.veiculo.ano,
            vin=payload.veiculo.vin,
            placa=payload.veiculo.placa,
            data_compra=payload.veiculo.data_compra,
            valor_compra=payload.veiculo.valor_compra,
            concessionaria_id=payload.veiculo.concessionaria_id,
        )
        self.db.add(veiculo)
        self.db.flush()

        features = ml_service.FeaturesCompra(
            regiao=cliente.regiao,
            modelo=veiculo.modelo,
            versao=veiculo.versao,
            ano=veiculo.ano,
            valor_compra=float(veiculo.valor_compra),
            concessionaria_id=veiculo.concessionaria_id,
        )
        resultado = ml_service.classificar(features)

        cliente.perfil = resultado.perfil
        cliente.score_risco = resultado.score_risco
        cliente.classificado_em = resultado.classificado_em

        self.audit.log_event(
            action=AuditAction.CLIENTE_CREATED,
            request=request,
            entity_type="Cliente",
            entity_id=str(cliente.id),
            details=f"perfil={resultado.perfil.value} score={resultado.score_risco}",
        )

        lead_id: Optional[UUID] = None
        if resultado.perfil in ml_service.PERFIS_GERAM_LEAD:
            lead = Lead(
                cliente_id=cliente.id,
                veiculo_id=veiculo.id,
                score_risco=resultado.score_risco,
                prioridade=ml_service.derivar_prioridade(resultado.score_risco),
                status=StatusLead.ABERTO,
                script_oferta=ml_service.script_para_perfil(resultado.perfil),
            )
            self.db.add(lead)
            self.db.flush()
            lead_id = lead.id
            self.audit.log_event(
                action=AuditAction.LEAD_CREATED,
                request=request,
                entity_type="Lead",
                entity_id=str(lead_id),
                details=f"prioridade={lead.prioridade.value}",
            )

        return ClienteCreatedResponse(
            cliente=cliente_to_output(cliente, self.crypto),
            lead_id=lead_id,
            perfil=resultado.perfil,
            score_risco=resultado.score_risco,
        )
