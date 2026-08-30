from fastapi import APIRouter
from app.routers.domains import router as domains_router
from app.routers.audits import router as audits_router
from app.routers.reports import router as reports_router

api_router = APIRouter()
api_router.include_router(domains_router, prefix="/domains", tags=["Domains"])
api_router.include_router(audits_router, prefix="/audits", tags=["Audits"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])