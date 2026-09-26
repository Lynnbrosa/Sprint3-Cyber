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


def _km_atual(vin: str) -> int:
    # odometro derivado do relogio (~180 km/h): sempre cresce entre execucoes do simulador.
    # com km aleatorio a cada run o ingestor via "odometro voltando" e recusava, com razao
    base = 60_000 + 7_000 * (VINS.index(vin) if vin in VINS else 0)
    return base + int((time.time() - 1_790_000_000) * 0.05)


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


def _conectar(ctx: ssl.SSLContext, client_id: str, espera: float = 5.0) -> tuple[mqtt.Client, dict]:
    """Conecta e espera o CONNACK. No TLS 1.3 o cliente termina o handshake antes de o broker
    validar o certificado dele, entao 'connect() nao deu erro' nao prova nada: vale o CONNACK."""
    estado: dict = {"connack": None, "desconexao": None, "pubacks": {}}
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv5)
    c.tls_set_context(ctx)
    c.on_connect = lambda _c, _u, _f, rc, _p: estado.update(connack=rc)
    c.on_disconnect = lambda _c, _u, _f, rc, _p: estado.update(desconexao=rc)
    c.on_publish = lambda _c, _u, mid, rc, _p: estado["pubacks"].__setitem__(mid, rc)
    c.connect(HOST, PORTA, keepalive=30)
    c.loop_start()
    limite = time.time() + espera
    while estado["connack"] is None and estado["desconexao"] is None and time.time() < limite:
        time.sleep(0.05)
    return c, estado


def _publicar(c: mqtt.Client, estado: dict, topico: str, corpo: bytes) -> str:
    info = c.publish(topico, corpo, qos=1)
    info.wait_for_publish(timeout=5)
    rc = estado["pubacks"].get(info.mid)
    if rc is None:
        return "sem PUBACK"
    return f"PUBACK {rc}" + (" (recusado)" if rc.is_failure else "")


def _handshake(ctx: ssl.SSLContext, rotulo: str) -> int:
    try:
        c, estado = _conectar(ctx, f"sim-{rotulo}", espera=4)
    except (ssl.SSLError, OSError) as e:
        print(f"[{rotulo}] recusado no handshake: {type(e).__name__}: {str(e)[:120]}")
        return 0
    c.loop_stop()
    rc = estado["connack"]
    if rc is not None and not rc.is_failure:
        print(f"[{rotulo}] FALHA DE CONTROLE: broker mandou CONNACK {rc}")
        return 1
    motivo = estado["desconexao"] or "conexao encerrada pelo broker"
    print(f"[{rotulo}] recusado pelo broker antes do CONNACK: {motivo} "
          "(log do mosquitto: 'peer did not return a certificate' / 'certificate verify failed')")
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

    c, estado = _conectar(_ctx(ca, cert, chave), f"veiculo-{a.vin}")
    if estado["connack"] is None or estado["connack"].is_failure:
        print(f"[{a.modo}] broker recusou o veiculo: {estado}")
        return 1
    km = _km_atual(a.vin)
    try:
        if a.modo == "topico-alheio":
            outro = VINS[1] if a.vin == VINS[0] else VINS[0]
            r = _publicar(c, estado, f"ford/telemetria/{outro}", json.dumps(_leitura(outro, km)).encode())
            print(f"[topico-alheio] {a.vin} tentou publicar em ford/telemetria/{outro}: {r} "
                  "(ACL por CN: o ingestor nao recebe nada)")
        elif a.modo == "payload-invalido":
            casos = {
                "campo_extra": {**_leitura(a.vin, km), "comando": "unlock_doors"},
                "odometro_negativo": {**_leitura(a.vin, km), "odometro_km": -5},
                "dtc_injecao": {**_leitura(a.vin, km), "codigos_falha": ["P0420'; DROP TABLE telemetria;--"]},
                "relogio_futuro": {**_leitura(a.vin, km), "ts": "2031-01-01T00:00:00Z"},
            }
            for nome, corpo in casos.items():
                r = _publicar(c, estado, f"ford/telemetria/{a.vin}", json.dumps(corpo).encode())
                print(f"[payload-invalido] {nome}: {r} (broker entrega; o ingestor valida e recusa)")
            r = _publicar(c, estado, f"ford/telemetria/{a.vin}", b"x" * 3000)
            print(f"[payload-invalido] payload_grande: {r}")
        elif a.modo == "odometro-regressivo":
            _publicar(c, estado, f"ford/telemetria/{a.vin}", json.dumps(_leitura(a.vin, km)).encode())
            time.sleep(0.5)
            r = _publicar(c, estado, f"ford/telemetria/{a.vin}", json.dumps(_leitura(a.vin, km - 8_000)).encode())
            print(f"[odometro-regressivo] {km} -> {km - 8000}: {r} (ingestor deve recusar)")
        else:
            for i in range(a.n):
                km = _km_atual(a.vin)
                r = _publicar(c, estado, f"ford/telemetria/{a.vin}", json.dumps(_leitura(a.vin, km)).encode())
                print(f"[normal] {a.vin} leitura {i + 1}/{a.n} km={km}: {r}")
                time.sleep(a.intervalo)
    finally:
        time.sleep(0.5)
        c.loop_stop()
        c.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
