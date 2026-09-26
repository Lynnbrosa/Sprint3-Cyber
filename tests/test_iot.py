"""Validação da telemetria MQTT (sem broker) e gravação pelo ingestor (com Postgres)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.iot.validacao import TelemetriaRecusada, aproximar, validar

VIN = "9BFZZZ8F7NB000001"
AGORA = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)


def _msg(**extra) -> bytes:
    base = {"vin": VIN, "ts": AGORA.isoformat(), "odometro_km": 15230, "velocidade_kmh": 60,
            "combustivel_pct": 40, "codigos_falha": ["P0420"], "lat": -23.561345, "lon": -46.656543}
    base.update(extra)
    return json.dumps(base).encode()


def test_leitura_valida_passa():
    d = validar(f"ford/telemetria/{VIN}", _msg(), agora=AGORA)
    assert d.odometro_km == 15230


@pytest.mark.parametrize("topico,payload,motivo", [
    ("ford/telemetria/../../admin", _msg(), "topico_invalido"),
    (f"ford/telemetria/{VIN}", b"x" * 3000, "payload_grande"),
    (f"ford/telemetria/{VIN}", b"{nao e json", "json_invalido"),
    (f"ford/telemetria/{VIN}", b"[1,2]", "json_invalido"),
    (f"ford/telemetria/{VIN}", _msg(comando="unlock_doors"), "schema"),
    (f"ford/telemetria/{VIN}", _msg(odometro_km=-5), "schema"),
    (f"ford/telemetria/{VIN}", _msg(velocidade_kmh=900), "schema"),
    (f"ford/telemetria/{VIN}", _msg(codigos_falha=["P0420'; DROP TABLE telemetria;--"]), "schema"),
    (f"ford/telemetria/{VIN}", _msg(ts="2026-09-26T12:00:00"), "schema"),
    (f"ford/telemetria/{VIN}", _msg(vin="9BFZZZ8F7NB000002"), "vin_divergente"),
    (f"ford/telemetria/{VIN}", _msg(ts=(AGORA + timedelta(hours=1)).isoformat()), "relogio"),
    (f"ford/telemetria/{VIN}", _msg(ts=(AGORA - timedelta(days=3)).isoformat()), "relogio"),
])
def test_telemetria_recusada(topico, payload, motivo):
    with pytest.raises(TelemetriaRecusada) as e:
        validar(topico, payload, agora=AGORA)
    assert e.value.motivo == motivo


def test_odometro_voltando_e_recusado():
    with pytest.raises(TelemetriaRecusada) as e:
        validar(f"ford/telemetria/{VIN}", _msg(odometro_km=9000), agora=AGORA, ultimo_odometro=15000)
    assert e.value.motivo == "odometro_regressivo"


def test_localizacao_e_generalizada():
    assert aproximar(-23.561345) == -23.56
    assert aproximar(None) is None


def test_ingestor_grava_so_o_valido_e_com_posicao_aproximada(db):
    from app.iot.ingestor import processar
    from app.models import Telemetria

    agora = datetime.now(timezone.utc).isoformat()
    assert processar(f"ford/telemetria/{VIN}", _msg(ts=agora)) is True
    assert processar(f"ford/telemetria/{VIN}", _msg(ts=agora, odometro_km=100)) is False
    linhas = db.query(Telemetria).all()
    assert len(linhas) == 1
    assert linhas[0].lat_aprox == -23.56 and linhas[0].lon_aprox == -46.66


def test_telemetria_velha_e_apagada(db):
    from app.models import Telemetria
    from app.services.retention_service import purge_telemetria

    velha = datetime.now(timezone.utc) - timedelta(days=120)
    db.add(Telemetria(vin=VIN, medido_em=velha, recebido_em=velha, odometro_km=1))
    db.add(Telemetria(vin=VIN, medido_em=AGORA, odometro_km=2))
    db.commit()
    assert purge_telemetria(db) == 1
    assert db.query(Telemetria).count() == 1
