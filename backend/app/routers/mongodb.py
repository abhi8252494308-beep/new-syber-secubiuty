from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from datetime import datetime, timedelta

from ..services.mongodb_service import get_mongodb_service

router = APIRouter()


@router.get("/statistics")
async def get_statistics(
    mongodb = Depends(get_mongodb_service)
):
    """Get overall audit statistics for dashboard"""
    try:
        stats = await mongodb.get_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audits/recent")
async def get_recent_audits(
    limit: int = Query(20, ge=1, le=100),
    mongodb = Depends(get_mongodb_service)
):
    """Get recent audit results"""
    try:
        audits = await mongodb.get_recent_audits(limit=limit)
        return audits
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audits/by-risk-score")
async def get_audits_by_risk_score(
    min_score: int = Query(0, ge=0, le=100),
    max_score: int = Query(100, ge=0, le=100),
    limit: int = Query(50, ge=1, le=100),
    mongodb = Depends(get_mongodb_service)
):
    """Get audits filtered by risk score"""
    try:
        audits = await mongodb.get_audits_by_risk_score(
            min_score=min_score, 
            max_score=max_score, 
            limit=limit
        )
        return audits
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audits/domain/{domain}")
async def get_audits_by_domain(
    domain: str,
    limit: int = Query(50, ge=1, le=100),
    mongodb = Depends(get_mongodb_service)
):
    """Get audit results for a specific domain"""
    try:
        audits = await mongodb.get_audit_results_by_domain(domain, limit=limit)
        return audits
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audits/{audit_id}")
async def get_audit_by_id(
    audit_id: str,
    mongodb = Depends(get_mongodb_service)
):
    """Get audit result by ID"""
    try:
        audit = await mongodb.get_audit_result(audit_id)
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found")
        return audit
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/domains")
async def get_domains(
    limit: int = Query(100, ge=1, le=500),
    mongodb = Depends(get_mongodb_service)
):
    """Get all domains"""
    try:
        domains = await mongodb.get_all_domains(limit=limit)
        return domains
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/domains/{domain}")
async def get_domain(
    domain: str,
    mongodb = Depends(get_mongodb_service)
):
    """Get domain by name"""
    try:
        domain_data = await mongodb.get_domain(domain)
        if not domain_data:
            raise HTTPException(status_code=404, detail="Domain not found")
        return domain_data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))