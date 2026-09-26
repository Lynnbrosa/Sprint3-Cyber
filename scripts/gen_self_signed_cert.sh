#!/usr/bin/env bash
set -euo pipefail

# Gera certificado TLS self-signed para o nginx em DEV.
# Em produção: use Let's Encrypt via certbot ou cert do CA corporativo.

OUT_DIR="${1:-./nginx/certs}"
mkdir -p "$OUT_DIR"

if [[ -f "$OUT_DIR/dev.crt" ]]; then
    echo "ja existe: $OUT_DIR/dev.crt — saindo sem sobrescrever"
    exit 0
fi

# MSYS_NO_PATHCONV=1 evita que Git Bash no Windows traduza o -subj "/C=BR/..." pra path absoluto.
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$OUT_DIR/dev.key" \
    -out    "$OUT_DIR/dev.crt" \
    -subj "/C=BR/ST=SP/L=Sao Paulo/O=PrevioPLS Dev/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:previopls.local,IP:127.0.0.1"

chmod 600 "$OUT_DIR/dev.key"
chmod 644 "$OUT_DIR/dev.crt"

echo "Cert TLS gerado em $OUT_DIR/"
echo "  AVISO: self-signed — navegador vai reclamar; aceite a exceção em DEV."
