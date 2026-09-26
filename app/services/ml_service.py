"""Stub do motor preditivo — replica a lógica do backend Java (SHA-256 dos features D0)."""
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from app.models import PerfilCliente, PrioridadeLead


PERFIS_GERAM_LEAD = {PerfilCliente.ABANDONO, PerfilCliente.ESQUECIDO}

SCRIPTS = {
    PerfilCliente.FIEL: (
        "Cliente fiel — oferecer pacote de manutenção preventiva premium "
        "e enfatizar histórico de relacionamento com a marca."
    ),
    PerfilCliente.ABANDONO: (
        "Cliente de alto risco de evasão — oferta agressiva de primeira revisão "
        "com desconto + brinde institucional."
    ),
    PerfilCliente.ESQUECIDO: (
        "Cliente esquecido — lembrete proativo de manutenção + agendamento facilitado."
    ),
    PerfilCliente.ECONOMICO: (
        "Cliente sensível a preço — apresentar oferta promocional com parcelamento."
    ),
}


@dataclass
class FeaturesCompra:
    regiao: str
    modelo: str
    versao: str
    ano: int
    valor_compra: float
    concessionaria_id: str


@dataclass
class ResultadoClassificacao:
    perfil: PerfilCliente
    score_risco: float
    classificado_em: datetime


def classificar(f: FeaturesCompra) -> ResultadoClassificacao:
    seed = f"{f.concessionaria_id}|{f.modelo}|{f.versao}|{f.regiao}".encode()
    digest = hashlib.sha256(seed).digest()
    bucket = digest[0] % 100
    score_base = digest[1] / 255.0

    if bucket < 35:
        perfil = PerfilCliente.FIEL
        score = round(0.10 + score_base * 0.20, 3)
    elif bucket < 60:
        perfil = PerfilCliente.ECONOMICO
        score = round(0.30 + score_base * 0.25, 3)
    elif bucket < 85:
        perfil = PerfilCliente.ESQUECIDO
        score = round(0.55 + score_base * 0.20, 3)
    else:
        perfil = PerfilCliente.ABANDONO
        score = round(0.78 + score_base * 0.22, 3)

    return ResultadoClassificacao(perfil=perfil, score_risco=score, classificado_em=datetime.now(timezone.utc))


def derivar_prioridade(score: float) -> PrioridadeLead:
    if score >= 0.85:
        return PrioridadeLead.CRITICA
    if score >= 0.65:
        return PrioridadeLead.ALTA
    if score >= 0.40:
        return PrioridadeLead.MEDIA
    return PrioridadeLead.BAIXA


def script_para_perfil(p: PerfilCliente) -> str:
    return SCRIPTS[p]
