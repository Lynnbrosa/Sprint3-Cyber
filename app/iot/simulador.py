"""
Simulador de veículo conectado. Além do modo normal, encena os ataques que o
broker e o ingestor precisam barrar, pra gerar evidência:

    python -m app.iot.simulador --modo normal --vin 9BFZZZ8F7NB000001 --n 20
    python -m app.iot.simulador --modo sem-certificado      # handshake recusado
    python -m app.iot.simulador --modo ca-falsa             # cert de outra CA
    python -m app.iot.simulador --modo texto-claro          # porta 1883 nao existe
    python -m app.iot.simulador --modo topico-alheio        # publica no VIN de outro
    python -m app.iot.simulador --modo payload-invalido     # schema/limites
    python -m app.iot.simulador --modo odometro-regressivo  # km voltando
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

HOST = os.environ.get("MQTT_HOST", "mosquitto")
PORTA = int(os.environ.get("MQTT_PORT", "8883"))
CERTS = os.environ.get("MQTT_CERTS_DIR", "/certs")
VINS = ("9BFZZZ8F7NB000001", "9BFZZZ8F7NB000002")


def _ctx(ca: str, cert: str | None = None, chave: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert:
        ctx.load_cert_chain(cert, chave)
    return ctx


def _leitura(vin: str, km: int) -> dict:
    return {
        "vin": vin,
        "ts": datetime.now(timezone.utc).isoformat(),
        "odometro_km": km,
        "velocidade_kmh": random.randint(0, 110),
        "combustivel_pct": random.randint(10, 100),
        "codigos_falha": random.choice([[], [], [], ["P0420"], ["P0301", "P0171"]]),
        "lat": -23.5613 + random.uniform(-0.05, 0.05),
        "lon": -46.6565 + random.uniform(-0.05, 0.05),
    }


def _conectar(ctx: ssl.SSLContext, client_id: str) -> mqtt.Client:
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv5)
    c.tls_set_context(ctx)
    c.connect(HOST, PORTA, keepalive=30)
    c.loop_start()
    return c


def _publicar(c: mqtt.Client, topico: str, corpo: bytes) -> str:
    info = c.publish(topico, corpo, qos=1)
    info.wait_for_publish(timeout=5)
    return "enviada" if info.is_published() else "sem_puback"


def _handshake(ctx: ssl.SSLContext, rotulo: str) -> int:
    try:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"sim-{rotulo}", protocol=mqtt.MQTTv5)
        c.tls_set_context(ctx)
        c.connect(HOST, PORTA, keepalive=10)
        c.loop_start()
        c.publish(f"ford/telemetria/{VINS[0]}", b"{}", qos=1).wait_for_publish(timeout=3)
        c.loop_stop()
        print(f"[{rotulo}] FALHA DE CONTROLE: broker aceitou a conexao")
        return 1
    except (ssl.SSLError, OSError, ValueError, RuntimeError) as e:
        print(f"[{rotulo}] recusado pelo broker: {type(e).__name__}: {str(e)[:120]}")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modo", default="normal")
    ap.add_argument("--vin", default=VINS[0])
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--intervalo", type=float, default=1.0)
    a = ap.parse_args()
    ca = f"{CERTS}/ca.crt"
    cert, chave = f"{CERTS}/{a.vin}.crt", f"{CERTS}/{a.vin}.key"

    if a.modo == "sem-certificado":
        return _handshake(_ctx(ca), "sem-certificado")
    if a.modo == "ca-falsa":
        falso = os.environ.get("MQTT_ATACANTE_DIR", "/certs-atacante")
        return _handshake(_ctx(ca, f"{falso}/clone.crt", f"{falso}/clone.key"), "ca-falsa")
    if a.modo == "texto-claro":
        try:
            socket.create_connection((HOST, 1883), timeout=3).close()
            print("[texto-claro] FALHA DE CONTROLE: porta 1883 aberta")
            return 1
        except OSError as e:
            print(f"[texto-claro] porta 1883 fechada: {type(e).__name__}")
            return 0

    c = _conectar(_ctx(ca, cert, chave), f"veiculo-{a.vin}")
    km = random.randint(12_000, 60_000)
    try:
        if a.modo == "topico-alheio":
            outro = VINS[1] if a.vin == VINS[0] else VINS[0]
            r = _publicar(c, f"ford/telemetria/{outro}", json.dumps(_leitura(outro, km)).encode())
            print(f"[topico-alheio] {a.vin} publicou em ford/telemetria/{outro}: {r} "
                  "(a ACL descarta; o ingestor nao recebe nada)")
        elif a.modo == "payload-invalido":
            casos = {
                "campo_extra": {**_leitura(a.vin, km), "comando": "unlock_doors"},
                "odometro_negativo": {**_leitura(a.vin, km), "odometro_km": -5},
                "dtc_injecao": {**_leitura(a.vin, km), "codigos_falha": ["P0420'; DROP TABLE telemetria;--"]},
                "relogio_futuro": {**_leitura(a.vin, km), "ts": "2031-01-01T00:00:00Z"},
            }
            for nome, corpo in casos.items():
                print(f"[payload-invalido] {nome}: {_publicar(c, f'ford/telemetria/{a.vin}', json.dumps(corpo).encode())}")
            print(f"[payload-invalido] payload_grande: {_publicar(c, f'ford/telemetria/{a.vin}', b'x' * 3000)}")
        elif a.modo == "odometro-regressivo":
            _publicar(c, f"ford/telemetria/{a.vin}", json.dumps(_leitura(a.vin, km)).encode())
            time.sleep(0.5)
            r = _publicar(c, f"ford/telemetria/{a.vin}", json.dumps(_leitura(a.vin, km - 8_000)).encode())
            print(f"[odometro-regressivo] {km} -> {km - 8000}: {r} (ingestor deve recusar)")
        else:
            for i in range(a.n):
                km += random.randint(5, 900)
                r = _publicar(c, f"ford/telemetria/{a.vin}", json.dumps(_leitura(a.vin, km)).encode())
                print(f"[normal] {a.vin} leitura {i + 1}/{a.n} km={km}: {r}")
                time.sleep(a.intervalo)
    finally:
        time.sleep(0.5)
        c.loop_stop()
        c.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
