from fastapi import Request
from slowapi import Limiter

from app.core.config import get_settings


_settings = get_settings()


def client_key(request: Request) -> str:
    # request.client ja vem resolvido pelo ProxyHeadersMiddleware do uvicorn, que so
    # aceita X-Forwarded-For do nginx (FORWARDED_ALLOW_IPS). com "*" qualquer um
    # trocava o header e ganhava bucket novo a cada requisicao
    return request.client.host if request.client else "desconhecido"


limiter = Limiter(
    key_func=client_key,
    default_limits=[_settings.rate_limit_global],
    headers_enabled=True,
    strategy="fixed-window",
    storage_uri=_settings.rate_limit_storage_uri,
)
