from pydantic import BaseModel, EmailStr, Field

from app.models import RolePapel


class LoginRequest(BaseModel):
    model_config = {"str_strip_whitespace": True, "extra": "forbid"}

    email: EmailStr = Field(..., max_length=180)
    senha: str = Field(..., min_length=6, max_length=128)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    access_expires_in: int
    refresh_expires_in: int
    role: RolePapel


class RefreshRequest(BaseModel):
    model_config = {"extra": "forbid"}

    refresh_token: str = Field(..., min_length=20, max_length=2048)
