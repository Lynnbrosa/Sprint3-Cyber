from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.hmac_signing import require_hmac_signature
from app.core.security import Role, requires_role
from app.db.session import get_db
from app.schemas.cliente import ClienteCreate, ClienteCreatedResponse
from app.services.cliente_service import ClienteService

router = APIRouter(prefix="/clientes", tags=["clientes"])


@router.post(
    "",
    response_model=ClienteCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(requires_role(Role.ADMIN)),
        Depends(require_hmac_signature),  # HMAC obrigatório em payload crítico (LGPD)
    ],
)
def criar_cliente(
    payload: ClienteCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> ClienteCreatedResponse:
    service = ClienteService(db)
    result = service.cadastrar_compra(payload, request)
    db.commit()
    return result
