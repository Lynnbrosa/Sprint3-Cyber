import time
import uuid

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings
from app.core.logging import get_logger


log = get_logger(__name__)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Garante correlation ID por requisição; injeta em logs e header de resposta."""

    HEADER = "X-Request-Id"

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(self.HEADER)
        if not rid or len(rid) > 64:
            rid = uuid.uuid4().hex

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=rid,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None,
        )

        request.state.request_id = rid
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception("request_failed")
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            log.info(
                "request_completed",
                status_code=getattr(response, "status_code", None) if "response" in locals() else None,
                duration_ms=round(elapsed_ms, 2),
            )

        response.headers[self.HEADER] = rid
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Headers OWASP secure baseline.

    O CSP restritivo (default-src 'none') é aplicado em endpoints de API
    — eles só respondem JSON e não devem carregar nenhum recurso de origem.

    Para os paths de documentação (/docs, /redoc, /openapi.json) usamos um
    CSP mais permissivo permitindo 'self' + inline + CDN do Swagger UI,
    senão o próprio Swagger UI fica em branco no navegador (sem CSS/JS).
    """

    DOC_PATHS = ("/docs", "/redoc", "/openapi.json")

    CSP_DOCS = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://cdn.jsdelivr.net https://fastapi.tiangolo.com; "
        "font-src 'self' data: https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )

    CSP_API = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )

        path = request.url.path
        is_docs = any(path.startswith(p) for p in self.DOC_PATHS)
        response.headers["Content-Security-Policy"] = self.CSP_DOCS if is_docs else self.CSP_API
        return response
