# imagem unica pra api, ingestor MQTT, simulador e certgen (muda so o comando)

# base pinada por digest: a tag 3.12-slim anda sozinha e o build deixa de ser reproduzivel.
# o dependabot (ecosystem docker) abre PR quando sai digest novo
ARG PYTHON_IMAGE=python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install -r requirements.txt

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="previopls-security-api" \
      org.opencontainers.image.description="API de seguranca PrevioPLS (Ford Challenge) + ingestor IoT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

# patches de seguranca do debian na hora do build (o trivy recusa CVE com correcao disponivel).
# sem curl/wget: o healthcheck usa python, e menos binario = menos ferramenta pro invasor
RUN apt-get update \
 && apt-get -y upgrade \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 app \
 && useradd -u 10001 -g app -s /usr/sbin/nologin -M -d /nonexistent app \
 && mkdir -p /app/keys /var/log/previopls \
 && chown app:app /app/keys /var/log/previopls

COPY --from=build /opt/venv /opt/venv

WORKDIR /app
# codigo pertence ao root e o processo roda como 10001: nao da pra reescrever a app em runtime
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini docker-entrypoint.sh ./
COPY scripts/gen_certs.py ./scripts/

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["sh", "/app/docker-entrypoint.sh"]
