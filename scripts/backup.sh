#!/usr/bin/env bash
# backup diario do postgres: dump -> cifra AES-256 (pbkdf2) -> sha256 -> retencao
#   BACKUP_PASSPHRASE=... ./scripts/backup.sh [pasta]
# a senha do backup NAO fica no mesmo lugar do backup (cofre / secret manager).
# em producao: backup gerenciado do Azure Database/RDS com PITR + copia cifrada em
# outra regiao/conta (imutavel), e este script vira o teste de restauracao mensal.
set -euo pipefail

DESTINO="${1:-./backups}"
: "${BACKUP_PASSPHRASE:?defina BACKUP_PASSPHRASE (nunca no mesmo disco do backup)}"
RETER_DIAS="${RETER_DIAS:-7}"
AGORA="$(date -u +%Y%m%dT%H%M%SZ)"
ARQ="$DESTINO/previopls-$AGORA.dump.enc"

mkdir -p "$DESTINO"
chmod 700 "$DESTINO"

# formato custom (-Fc) permite restaurar tabela a tabela; o dump nunca toca o disco em claro
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner' \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:BACKUP_PASSPHRASE -out "$ARQ"

sha256sum "$ARQ" > "$ARQ.sha256"
chmod 600 "$ARQ" "$ARQ.sha256"

# retencao: backups mais velhos que RETER_DIAS saem (a trilha de 5 anos esta no proprio banco)
find "$DESTINO" -name 'previopls-*.dump.enc*' -mtime +"$RETER_DIAS" -print -delete

echo "backup ok: $ARQ ($(du -h "$ARQ" | cut -f1))"
