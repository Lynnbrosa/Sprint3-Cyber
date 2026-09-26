from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text

from app.api.v1 import api_v1
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestIdMiddleware, SecurityHeadersMiddleware
from app.core.ratelimit import limiter
from app.db.session import engine


configure_logging()
log = get_logger(__name__)


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="PrevioPLS Security API",
        version=settings.app_version,
        docs_url="/docs" if not settings.is_prod else None,
        redoc_url=None,
        openapi_url="/openapi.json" if not settings.is_prod else None,
    )

    # Middlewares (ordem importa: o último registrado é o mais externo).
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-Id", "X-Signature", "X-Timestamp"],
        expose_headers=["X-Request-Id"],
        max_age=3600,
    )
    app.add_middleware(RequestIdMiddleware)

    # Rate limit (slowapi anexa state ao app + exception handler)
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(_request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": f"Limite excedido: {exc.detail}",
                }
            },
            headers={"Retry-After": "60"},
        )

    register_exception_handlers(app)

    app.include_router(api_v1)

    @app.get("/health", tags=["meta"])
    def health():
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {"status": "ok", "components": {"database": "up"}}
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "degraded", "components": {"database": "down"}},
            )

    @app.get("/version", tags=["meta"])
    def version():
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "build_time": datetime.now(timezone.utc).isoformat(),
        }

    log.info("app.started", env=settings.app_env, version=settings.app_version)
    return app


app = create_app()
