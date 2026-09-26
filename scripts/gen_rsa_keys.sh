#!/usr/bin/env bash
set -euo pipefail

# Gera par RSA 2048 bits para assinar JWT RS256.
# Para produção use HSM/KMS — NUNCA mantenha a chave privada em disco do servidor.

OUT_DIR="${1:-./keys}"
mkdir -p "$OUT_DIR"

if [[ -f "$OUT_DIR/jwt_private.pem" ]]; then
    echo "ja existe: $OUT_DIR/jwt_private.pem — saindo sem sobrescrever"
    exit 0
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT_DIR/jwt_private.pem"
openssl rsa -in "$OUT_DIR/jwt_private.pem" -pubout -out "$OUT_DIR/jwt_public.pem"
chmod 600 "$OUT_DIR/jwt_private.pem"
chmod 644 "$OUT_DIR/jwt_public.pem"

echo "Chaves geradas em $OUT_DIR/"
echo "  - jwt_private.pem (manter privada)"
echo "  - jwt_public.pem  (distribuir para validação)"
