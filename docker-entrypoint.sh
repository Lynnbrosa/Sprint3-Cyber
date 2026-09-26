#!/bin/sh
# espera o postgres, aplica as migrations e sobe o uvicorn.
# FORWARDED_ALLOW_IPS = so o IP/rede do nginx. com "*" qualquer cliente forja X-Forwarded-For
set -eu

MAX_WAIT="${DB_WAIT_SECONDS:-60}"
elapsed=0
until python -c "from sqlalchemy import create_engine, text; from app.core.config import get_settings; create_engine(get_settings().database_url).connect().execute(text('SELECT 1'))" >/dev/null 2>&1
do
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "api: banco indisponivel apos ${MAX_WAIT}s" >&2
        exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    alembic upgrade head
fi

exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "${PORT:-8000}" \
    --proxy-headers \
    --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
    --no-server-header \
    "$@"
