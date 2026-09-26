from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.core.ratelimit import limiter
from app.core.security import Principal, current_principal
from app.db.session import get_db
from app.schemas.auth import LoginRequest, RefreshRequest, TokenPair
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenPair)
@limiter.limit("5/minute")
def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenPair:
    service = AuthService(db)
    tokens = service.login(payload.email, payload.senha, request)
    db.commit()
    return tokens


@router.post("/refresh", response_model=TokenPair)
@limiter.limit("20/minute")
def refresh(
    request: Request,
    response: Response,
    payload: RefreshRequest,
    db: Session = Depends(get_db),
) -> TokenPair:
    service = AuthService(db)
    tokens = service.refresh(payload.refresh_token, request)
    db.commit()
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    payload: RefreshRequest,
    db: Session = Depends(get_db),
    _: Principal = Depends(current_principal),
):
    service = AuthService(db)
    service.logout(payload.refresh_token, request)
    db.commit()
