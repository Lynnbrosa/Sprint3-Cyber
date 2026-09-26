#!/usr/bin/env bash
# teste de restauracao (mensal): prova que o backup volta, sem tocar o banco de producao.
#   BACKUP_PASSPHRASE=... ./scripts/restore_test.sh backups/previopls-<data>.dump.enc
# 1. confere o sha256  2. decifra direto no pg_restore de um banco descartavel
# 3. compara contagem de linhas das tabelas criticas  4. derruba o banco temporario
set -euo pipefail

ARQ="${1:?informe o arquivo .dump.enc}"
: "${BACKUP_PASSPHRASE:?defina BACKUP_PASSPHRASE}"
TEMP_DB="restore_teste_$(date +%s)"

sha256sum -c "$ARQ.sha256"

docker compose exec -T db sh -c "createdb -U \"\$POSTGRES_USER\" $TEMP_DB"
trap 'docker compose exec -T db sh -c "dropdb -U \"\$POSTGRES_USER\" --if-exists '"$TEMP_DB"'"' EXIT

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -in "$ARQ" \
  | docker compose exec -T db sh -c "pg_restore -U \"\$POSTGRES_USER\" -d $TEMP_DB --no-owner --exit-on-error"

for t in usuarios clientes leads audit_logs telemetria; do
  prod=$(docker compose exec -T db sh -c "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -tAc 'select count(*) from $t'")
  rest=$(docker compose exec -T db sh -c "psql -U \"\$POSTGRES_USER\" -d $TEMP_DB -tAc 'select count(*) from $t'")
  echo "$t: producao=$prod restaurado=$rest"
done
echo "restauracao ok em $TEMP_DB (removido ao sair)"
