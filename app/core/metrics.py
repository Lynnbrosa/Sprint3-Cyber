"""
Métricas Prometheus da API.

Todo evento de auditoria vira previopls_security_events_total{action=...}, então
alerta e dashboard saem da mesma fonte da trilha LGPD sem código duplicado.
O label de rota é o template (/v1/leads/{lead_id}), nunca o path cru: path cru
com UUID explode a cardinalidade e derruba o Prometheus.
"""
import re
import time

from fastapi import Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

HTTP_REQUESTS = Counter(
    "previopls_http_requests_total", "Requisições HTTP por rota e status", ["method", "route", "status"]
)
HTTP_LATENCY = Histogram(
    "previopls_http_request_duration_seconds", "Latência HTTP por rota", ["method", "route"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
SECURITY_EVENTS = Counter(
    "previopls_security_events_total", "Eventos da trilha de auditoria por ação", ["action"]
)
TOKENS_REJECTED = Counter(
    "previopls_auth_tokens_rejected_total", "Tokens recusados por motivo", ["reason"]
)
RATE_LIMITED = Counter(
    "previopls_rate_limited_total", "Requisições barradas pelo rate limit", ["route"]
)
LOGINS = Counter(
    "previopls_logins_total", "Tentativas de login por resultado e tipo de cliente", ["result", "client"]
)
ML_PREDICTIONS = Counter(
    "previopls_ml_predictions_total", "Classificações D0 por perfil", ["perfil"]
)
ML_LATENCY = Histogram(
    "previopls_ml_inference_seconds", "Tempo de inferência do classificador",
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5),
)
ML_SCORE = Histogram(
    "previopls_ml_score_risco", "Distribuição do score de risco (drift)",
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

CLIENTES_CONHECIDOS = {"mobile", "web", "integracao"}


def client_type(request: Request) -> str:
    valor = (request.headers.get("X-Client") or "").lower()
    return valor if valor in CLIENTES_CONHECIDOS else "outro"


def route_label(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if not template:
        return "sem_rota"
    # com router aninhado (fastapi 0.14x) route.path vem sem o prefixo /v1: acha onde
    # a regex da rota casa no fim do path e recoloca o prefixo, sem expor valor de parametro
    path = request.scope.get("path", "")
    regex = getattr(route, "path_regex", None)
    if regex is not None:
        m = re.search(regex.pattern.lstrip("^"), path)
        if m and m.start() > 0:
            return path[: m.start()] + template
    return template


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        inicio = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            rota = route_label(request)
            if rota != "/metrics":
                HTTP_REQUESTS.labels(request.method, rota, str(status)).inc()
                HTTP_LATENCY.labels(request.method, rota).observe(time.perf_counter() - inicio)


def metrics_response() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
