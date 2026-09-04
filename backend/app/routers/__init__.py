from fastapi import APIRouter
from .domains import router as domains_router
from .audits import router as audits_router
from .reports import router as reports_router
from .mongodb import router as mongodb_router

api_router = APIRouter()
api_router.include_router(domains_router, prefix="/domains", tags=["Domains"])
api_router.include_router(audits_router, prefix="/audits", tags=["Audits"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])
api_router.include_router(mongodb_router, prefix="/mongodb", tags=["MongoDB"])