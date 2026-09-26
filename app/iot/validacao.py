"""
Validação da telemetria que chega pelo MQTT. Fica separada do ingestor pra
ser testada sem broker.

O broker já garante quem publica (mTLS + ACL por VIN). Aqui entra o que o
broker não enxerga: formato, faixa de valor, relógio do device e odômetro
voltando (adulteração clássica de km pra fugir de revisão/garantia).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field, ValidationError, field_validator

VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
DTC_RE = re.compile(r"^[PBCU][0-3][0-9A-F]{3}$")
TOPICO_RE = re.compile(r"^ford/telemetria/([A-HJ-NPR-Z0-9]{17})$")
MAX_PAYLOAD_BYTES = 2048
# device offline guarda leitura; mais que 24h atras ou 2 min no futuro e relogio errado ou replay
MAX_ATRASO = timedelta(hours=24)
MAX_ADIANTADO = timedelta(minutes=2)


class TelemetriaPayload(BaseModel):
    model_config = {"extra": "forbid", "str_strip_whitespace": True}

    vin: str = Field(..., min_length=17, max_length=17)
    ts: datetime
    odometro_km: int = Field(..., ge=0, le=2_000_000)
    velocidade_kmh: int | None = Field(default=None, ge=0, le=300)
    combustivel_pct: int | None = Field(default=None, ge=0, le=100)
    codigos_falha: list[str] = Field(default_factory=list, max_length=10)
    lat: float | None = Field(default=None, ge=-90, le=90)
    lon: float | None = Field(default=None, ge=-180, le=180)

    @field_validator("vin")
    @classmethod
    def _vin(cls, v: str) -> str:
        if not VIN_RE.match(v):
            raise ValueError("VIN invalido")
        return v

    @field_validator("codigos_falha")
    @classmethod
    def _dtc(cls, v: list[str]) -> list[str]:
        for c in v:
            if not DTC_RE.match(c):
                raise ValueError(f"codigo OBD-II invalido: {c[:8]!r}")
        return v

    @field_validator("ts")
    @classmethod
    def _ts(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("ts precisa de fuso (ISO 8601 com Z ou offset)")
        return v


class TelemetriaRecusada(Exception):
    def __init__(self, motivo: str, detalhe: str = "") -> None:
        super().__init__(motivo)
        self.motivo = motivo
        self.detalhe = detalhe


def validar(topico: str, payload: bytes, *, agora: datetime | None = None,
            ultimo_odometro: int | None = None) -> TelemetriaPayload:
    agora = agora or datetime.now(timezone.utc)

    m = TOPICO_RE.match(topico)
    if not m:
        raise TelemetriaRecusada("topico_invalido")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise TelemetriaRecusada("payload_grande", f"{len(payload)} bytes")
    try:
        bruto = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        raise TelemetriaRecusada("json_invalido") from None
    if not isinstance(bruto, dict):
        raise TelemetriaRecusada("json_invalido")
    try:
        dado = TelemetriaPayload.model_validate(bruto)
    except ValidationError as e:
        campos = ",".join(str(err["loc"][0]) for err in e.errors() if err.get("loc"))
        raise TelemetriaRecusada("schema", campos) from None

    # a ACL ja amarra topico ao CN; o VIN do corpo tambem tem que bater
    if dado.vin != m.group(1):
        raise TelemetriaRecusada("vin_divergente")
    if dado.ts < agora - MAX_ATRASO or dado.ts > agora + MAX_ADIANTADO:
        raise TelemetriaRecusada("relogio", dado.ts.isoformat())
    if ultimo_odometro is not None and dado.odometro_km < ultimo_odometro:
        raise TelemetriaRecusada("odometro_regressivo", f"{ultimo_odometro} -> {dado.odometro_km}")
    return dado


def aproximar(coord: float | None) -> float | None:
    """2 casas decimais ~ 1,1 km: suficiente pra regiao/concessionaria, insuficiente pra endereco."""
    return None if coord is None else round(coord, 2)
