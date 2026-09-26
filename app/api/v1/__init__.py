from fastapi import APIRouter

from app.api.v1 import audit, auth, clientes, leads, llm

api_v1 = APIRouter(prefix="/v1")
api_v1.include_router(auth.router)
api_v1.include_router(clientes.router)
api_v1.include_router(leads.router)
api_v1.include_router(llm.router)
api_v1.include_router(audit.router)
