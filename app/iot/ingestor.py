"""
Ingestor de telemetria: assina ford/telemetria/+ no mosquitto com mTLS, valida
cada mensagem e grava. Métricas em :9101/metrics.

    python -m app.iot.ingestor
"""
from __future__ import annotations

import os
import signal
import ssl
import sys

import paho.mqtt.client as mqtt
from prometheus_client import Counter, Gauge, start_http_server
from sqlalchemy import select

from app.core.logging import configure_logging, get_logger
from app.db.session import SessionLocal
from app.iot.validacao import TelemetriaRecusada, aproximar, validar
from app.models import Telemetria

configure_logging()
log = get_logger("iot.ingestor")

MENSAGENS = Counter("previopls_iot_messages_total", "Mensagens de telemetria", ["result", "motivo"])
REVISOES = Counter("previopls_iot_revisoes_devidas_total", "Veiculos que cruzaram marco de revisao")
CONECTADO = Gauge("previopls_iot_broker_connected", "1 quando o ingestor esta conectado ao broker")
REVISAO_KM = 10_000

HOST = os.environ.get("MQTT_HOST", "mosquitto")
PORTA = int(os.environ.get("MQTT_PORT", "8883"))
CERTS = os.environ.get("MQTT_CERTS_DIR", "/certs")


def contexto_tls(ca: str, cert: str, chave: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, chave)
    return ctx  # check_hostname=True: o CN/SAN do broker tem que bater com MQTT_HOST


def _ultimo_odometro(db, vin: str) -> int | None:
    return db.scalar(
        select(Telemetria.odometro_km).where(Telemetria.vin == vin)
        .order_by(Telemetria.medido_em.desc()).limit(1)
    )


def processar(topico: str, payload: bytes) -> bool:
    with SessionLocal() as db:
        vin = topico.rsplit("/", 1)[-1][:17]
        anterior = _ultimo_odometro(db, vin)
        try:
            dado = validar(topico, payload, ultimo_odometro=anterior)
        except TelemetriaRecusada as e:
            MENSAGENS.labels("rejeitada", e.motivo).inc()
            nivel = log.warning if e.motivo in ("vin_divergente", "odometro_regressivo") else log.info
            nivel("iot.telemetria_rejeitada", motivo=e.motivo, detalhe=e.detalhe, vin=vin, security=True)
            return False

        db.add(Telemetria(
            vin=dado.vin, medido_em=dado.ts, odometro_km=dado.odometro_km,
            velocidade_kmh=dado.velocidade_kmh, combustivel_pct=dado.combustivel_pct,
            codigos_falha=",".join(dado.codigos_falha) or None,
            lat_aprox=aproximar(dado.lat), lon_aprox=aproximar(dado.lon),
        ))
        db.commit()
        MENSAGENS.labels("aceita", "ok").inc()
        # cruzou multiplo de 10 mil km: gancho pro lead de revisao no core
        if anterior is not None and dado.odometro_km // REVISAO_KM > anterior // REVISAO_KM:
            REVISOES.inc()
            log.info("iot.revisao_devida", vin=dado.vin, odometro_km=dado.odometro_km)
        log.info("iot.telemetria_aceita", vin=dado.vin, odometro_km=dado.odometro_km,
                 falhas=len(dado.codigos_falha))
        return True


def _on_connect(client, _userdata, _flags, reason_code, _props):
    if reason_code.is_failure:
        CONECTADO.set(0)
        log.error("iot.broker_recusou", motivo=str(reason_code))
        return
    CONECTADO.set(1)
    client.subscribe("ford/telemetria/+", qos=1)
    log.info("iot.conectado", broker=f"{HOST}:{PORTA}")


def _on_disconnect(_client, _userdata, _flags, reason_code, _props):
    CONECTADO.set(0)
    log.warning("iot.desconectado", motivo=str(reason_code))


def _on_message(_client, _userdata, msg):
    try:
        processar(msg.topic, msg.payload)
    except Exception as exc:  # uma mensagem ruim nao derruba o consumidor
        MENSAGENS.labels("erro", type(exc).__name__).inc()
        log.error("iot.erro_processamento", erro=type(exc).__name__)


def main() -> int:
    start_http_server(int(os.environ.get("METRICS_PORT", "9101")))
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ingestor", protocol=mqtt.MQTTv5)
    client.tls_set_context(contexto_tls(f"{CERTS}/ca.crt", f"{CERTS}/ingestor.crt", f"{CERTS}/ingestor.key"))
    client.on_connect = _on_connect
    client.on_disconnect = _on_disconnect
    client.on_message = _on_message
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    signal.signal(signal.SIGTERM, lambda *_: client.disconnect())
    client.connect(HOST, PORTA, keepalive=60)
    client.loop_forever(retry_first_connection=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
