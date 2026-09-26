"""
Gera os certificados de desenvolvimento (roda no container certgen do compose, uma vez):

  /out/ca          CA interna (chave fica só aqui, nenhum outro container monta este volume)
  /out/nginx       TLS do nginx (localhost)
  /out/broker      mosquitto: server.crt/key + ca.crt
  /out/ingestor    cliente MQTT do ingestor (CN=ingestor) + ca.crt
  /out/veiculos    um par por VIN de demo (CN=VIN) + ca.crt
  /out/atacante    CA falsa e cliente assinado por ela, só pra demonstrar a recusa

Em produção: CA em HSM/KMS (AWS Private CA, Vault PKI), certificado de veículo
provisionado na fábrica e com validade curta. Nada disso sai desta pasta pro git.

    python scripts/gen_certs.py [--out ./certs] [--uid-api 10001] [--uid-broker 1883] [--uid-nginx 101]
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VINS_DEMO = ("9BFZZZ8F7NB000001", "9BFZZZ8F7NB000002")
AGORA = dt.datetime.now(dt.timezone.utc)


def _chave():
    return ec.generate_private_key(ec.SECP256R1())


def _nome(cn: str, org: str = "PrevioPLS Dev") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _salvar(pasta: Path, nome: str, cert: x509.Certificate, chave=None, uid: int | None = None) -> None:
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / f"{nome}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if chave is not None:
        k = pasta / f"{nome}.key"
        k.write_bytes(chave.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))
        os.chmod(k, 0o600)
        if uid is not None and hasattr(os, "chown"):
            os.chown(k, uid, uid)


def _ca(cn: str, org: str):
    chave = _chave()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_nome(cn, org)).issuer_name(_nome(cn, org))
        .public_key(chave.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(AGORA - dt.timedelta(minutes=5)).not_valid_after(AGORA + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(chave, hashes.SHA256())
    )
    return cert, chave


def _emitir(ca_cert, ca_key, cn: str, *, servidor: bool, sans: list[str] | None = None, dias: int = 397):
    chave = _chave()
    uso = ExtendedKeyUsageOID.SERVER_AUTH if servidor else ExtendedKeyUsageOID.CLIENT_AUTH
    b = (
        x509.CertificateBuilder()
        .subject_name(_nome(cn)).issuer_name(ca_cert.subject)
        .public_key(chave.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(AGORA - dt.timedelta(minutes=5)).not_valid_after(AGORA + dt.timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([uso]), critical=False)
    )
    if sans:
        nomes = []
        for s in sans:
            try:
                nomes.append(x509.IPAddress(ipaddress.ip_address(s)))
            except ValueError:
                nomes.append(x509.DNSName(s))
        b = b.add_extension(x509.SubjectAlternativeName(nomes), critical=False)
    return b.sign(ca_key, hashes.SHA256()), chave


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    ap.add_argument("--uid-api", type=int, default=10001)
    ap.add_argument("--uid-broker", type=int, default=1883)
    ap.add_argument("--uid-nginx", type=int, default=101)
    ap.add_argument("--log-nginx", default="", help="volume de log do nginx a entregar pro uid do nginx")
    a = ap.parse_args()
    out = Path(a.out)

    # volume nomeado nasce root; o nginx sem privilegio (uid 101) nao escreveria nele
    if a.log_nginx:
        Path(a.log_nginx).mkdir(parents=True, exist_ok=True)
        if hasattr(os, "chown"):
            os.chown(a.log_nginx, a.uid_nginx, a.uid_nginx)

    if (out / "ca" / "ca.crt").exists():
        print("certgen: certificados ja existem, nada a fazer")
        return

    ca_cert, ca_key = _ca("PrevioPLS Dev CA", "PrevioPLS Dev")
    _salvar(out / "ca", "ca", ca_cert, ca_key)

    nginx_cert, nginx_key = _emitir(ca_cert, ca_key, "localhost", servidor=True,
                                    sans=["localhost", "previopls.local", "127.0.0.1"])
    _salvar(out / "nginx", "tls", nginx_cert, nginx_key, uid=a.uid_nginx)
    _salvar(out / "nginx", "ca", ca_cert)

    srv_cert, srv_key = _emitir(ca_cert, ca_key, "mosquitto", servidor=True, sans=["mosquitto", "localhost", "127.0.0.1"])
    _salvar(out / "broker", "server", srv_cert, srv_key, uid=a.uid_broker)
    _salvar(out / "broker", "ca", ca_cert)

    ing_cert, ing_key = _emitir(ca_cert, ca_key, "ingestor", servidor=False)
    _salvar(out / "ingestor", "ingestor", ing_cert, ing_key, uid=a.uid_api)
    _salvar(out / "ingestor", "ca", ca_cert)

    for vin in VINS_DEMO:
        # certificado de veiculo curto: se vazar, morre sozinho em 90 dias
        v_cert, v_key = _emitir(ca_cert, ca_key, vin, servidor=False, dias=90)
        _salvar(out / "veiculos", vin, v_cert, v_key, uid=a.uid_api)
    _salvar(out / "veiculos", "ca", ca_cert)

    falsa_cert, falsa_key = _ca("CA do Atacante", "Oficina Paralela")
    rogue_cert, rogue_key = _emitir(falsa_cert, falsa_key, VINS_DEMO[0], servidor=False)
    _salvar(out / "atacante", "clone", rogue_cert, rogue_key, uid=a.uid_api)
    _salvar(out / "atacante", "ca", ca_cert)

    print(f"certgen: CA, nginx, broker, ingestor, {len(VINS_DEMO)} veiculos e cliente falso gerados em {out}")


if __name__ == "__main__":
    main()
