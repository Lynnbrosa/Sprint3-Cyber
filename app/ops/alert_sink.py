"""
Receptor de alertas do ambiente de demo: faz o papel do Slack/PagerDuty/SIEM.

Recebe o webhook do Alertmanager (/api/alertmanager) e o da propria api
(/api/alerta, SECURITY_ALERT_WEBHOOK_URL), e grava cada um como incidente em
JSON (stdout + arquivo lido pelo promtail). Em producao o Alertmanager aponta
pro canal de plantao e este servico nao existe.

    python -m app.ops.alert_sink
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prometheus_client import Counter, start_http_server

from app.core.logging import configure_logging, get_logger

configure_logging()
log = get_logger("ops.alert_sink")

RECEBIDOS = Counter("previopls_alertas_recebidos_total", "Alertas recebidos pelo sink", ["origem", "severidade"])
MAX_BODY = 64 * 1024


def _severidade(alerta: dict) -> str:
    return str(alerta.get("labels", {}).get("severity", alerta.get("severity", "info")))[:20]


class Handler(BaseHTTPRequestHandler):
    server_version = "alert-sink"
    sys_version = ""

    def log_message(self, *_):  # o log de acesso padrao vai pro stderr sem formato
        return

    def _responder(self, codigo: int) -> None:
        self.send_response(codigo)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):  # noqa: N802
        tamanho = int(self.headers.get("Content-Length") or 0)
        if tamanho <= 0 or tamanho > MAX_BODY:
            return self._responder(413)
        try:
            corpo = json.loads(self.rfile.read(tamanho))
        except ValueError:
            return self._responder(400)

        if self.path == "/api/alertmanager":
            for alerta in corpo.get("alerts", [])[:50]:
                sev = _severidade(alerta)
                RECEBIDOS.labels("alertmanager", sev).inc()
                log.warning(
                    "incidente.alerta",
                    incidente_id=uuid.uuid4().hex[:12],
                    origem="alertmanager",
                    status=alerta.get("status"),
                    alerta=alerta.get("labels", {}).get("alertname"),
                    severidade=sev,
                    resumo=alerta.get("annotations", {}).get("summary"),
                    runbook=alerta.get("annotations", {}).get("runbook"),
                    inicio=alerta.get("startsAt"),
                    security=True,
                )
        elif self.path == "/api/alerta":
            RECEBIDOS.labels("api", "high").inc()
            log.warning("incidente.alerta", incidente_id=uuid.uuid4().hex[:12], origem="api",
                        alerta=str(corpo.get("type"))[:40], detalhes=corpo, security=True,
                        recebido_em=datetime.now(timezone.utc).isoformat())
        else:
            return self._responder(404)
        return self._responder(202)


def main() -> None:
    start_http_server(int(os.environ.get("METRICS_PORT", "9102")))
    porta = int(os.environ.get("PORT", "9095"))
    log.info("alert_sink.started", porta=porta)
    ThreadingHTTPServer(("0.0.0.0", porta), Handler).serve_forever()  # nosec B104 - rede interna do compose


if __name__ == "__main__":
    main()
