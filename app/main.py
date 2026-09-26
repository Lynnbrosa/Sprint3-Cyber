from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text

from app.api.v1 import api_v1
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.metrics import RATE_LIMITED, MetricsMiddleware, inicializar_series, metrics_response, route_label
from app.core.middleware import RequestIdMiddleware, SecurityHeadersMiddleware
from app.core.ratelimit import limiter
from app.core.security import ensure_jwt_keys
from app.db.session import SessionLocal, engine


configure_logging()
log = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    ensure_jwt_keys()

    from app.db.seed import bootstrap_admin, seed_default_users

    try:
        with SessionLocal() as db:
            bootstrap_admin(db)
            if settings.should_seed_default_users:
                criados = seed_default_users(db)
                log.warning("seed.demo_users", created=criados, hint="desligue com SEED_DEFAULT_USERS=false")
    except Exception as exc:  # sem banco a api sobe e o /health mostra degraded
        log.error("seed.failed", error=type(exc).__name__)

    log.info("app.started", env=settings.app_env, version=settings.app_version)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    inicializar_series()

    app = FastAPI(
        title="PrevioPLS Security API",
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_prod else None,
        redoc_url=None,
        openapi_url="/openapi.json" if not settings.is_prod else None,
    )

    # Middlewares (ordem importa: o último registrado é o mais externo).
    # sem o SlowAPIMiddleware o default_limits (100/min) nao valia pra rota nenhuma,
    # so as que tinham @limiter.limit explicito
    app.add_middleware(SlowAPIMiddleware)
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
    app.add_middleware(MetricsMiddleware)

    # Rate limit (slowapi anexa state ao app + exception handler)
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        log.warning("rate_limit.exceeded", limite=str(exc.detail), path=request.url.path)
        RATE_LIMITED.labels(route_label(request)).inc()
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
    @limiter.exempt
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

    @app.get("/metrics", include_in_schema=False)
    @limiter.exempt
    def metrics(request: Request):
        # o nginx devolve 404 pra /metrics; quem raspa e o prometheus pela rede interna.
        # com METRICS_TOKEN definido, exige Bearer tambem (defesa em profundidade)
        token = settings.metrics_token
        if token and request.headers.get("Authorization") != f"Bearer {token}":
            return JSONResponse(status_code=401, content={"error": {"code": "UNAUTHORIZED", "message": "token de metricas"}})
        return metrics_response()

    @app.get("/version", tags=["meta"])
    def version():
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "build_time": datetime.now(timezone.utc).isoformat(),
        }

    return app


app = create_app()
