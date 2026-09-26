"""
Endpoint de consulta a provedor de LLM externo.

Diferencial do produto: enquanto os 4 scripts comerciais por perfil cobrem 95%
dos leads, este endpoint permite que o consultor solicite um script refinado
para casos atípicos (cliente de alto valor, perfil ambíguo, histórico
incomum). A LLM recebe contexto agregado (perfil + score + dados D0 +
região) e devolve sugestão contextualizada.

Rate limit agressivo (10 req/min) porque chamadas a LLM têm custo financeiro
e podem ser exploradas para data exfiltration via prompt injection — só
Admin e Analista podem chamar.
"""
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.ratelimit import limiter
from app.core.security import Principal, Role, requires_role


router = APIRouter(prefix="/llm-assist", tags=["llm"])


class LlmRequest(BaseModel):
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}

    prompt: str = Field(..., min_length=1, max_length=4000)


class LlmResponse(BaseModel):
    response: str
    model: str


@router.post("", response_model=LlmResponse)
@limiter.limit(get_settings().rate_limit_llm)
def consult(
    request: Request,
    response: Response,
    payload: LlmRequest,
    principal: Principal = Depends(requires_role(Role.ADMIN, Role.ANALISTA)),
) -> LlmResponse:
    """
    Stub: em produção, encaminha para o provedor de LLM contratado (Anthropic
    Claude / OpenAI / AWS Bedrock — decisão de procurement) com o contexto
    do lead, e retorna sugestão de abordagem comercial customizada.
    """
    return LlmResponse(
        response=f"[STUB] Sugestão de abordagem para: {payload.prompt[:80]}...",
        model="llm-stub-v1",
    )
