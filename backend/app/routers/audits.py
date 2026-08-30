import asyncio
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from uuid import UUID

from app.database import get_db
from app.schemas.audit import AuditCreate, AuditResponse, AuditSummary
from app.services.audit_engine import AuditEngine
from app.models.audit import Audit, AuditResult, TLSResult, HeaderResult, CookieResult, RobotsResult, SecurityTxtResult, ServerInfoResult
from app.models.domain import Domain

router = APIRouter()


async def run_audit_background(audit_id: str, domain_id: str):
    """Run audit in background"""
    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        try:
            # Get domain
            result = await db.execute(
                select(Domain).where(Domain.id == str(domain_id))
            )
            domain = result.scalar_one_or_none()
            if not domain:
                return

            # Run audit
            engine = AuditEngine()
            await engine.run_audit(db, domain, audit_id=str(audit_id))
        except Exception as e:
            # Update audit with error
            result = await db.execute(
                select(Audit).where(Audit.id == str(audit_id))
            )
            audit = result.scalar_one_or_none()
            if audit:
                audit.status = "failed"
                audit.error_message = str(e)
                await db.commit()


@router.post("", response_model=AuditResponse, status_code=status.HTTP_201_CREATED)
async def create_audit(
    audit_data: AuditCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create a new audit for a domain"""
    # Verify domain exists
    result = await db.execute(
        select(Domain).where(Domain.id == str(audit_data.domain_id))
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    if not domain.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain is not verified. Please verify the domain first.",
        )

    # Create audit
    audit = Audit(
        domain_id=str(audit_data.domain_id),
        status="pending",
    )
    db.add(audit)
    await db.commit()
    await db.refresh(audit)

    # Run audit in background
    background_tasks.add_task(
        run_audit_background,
        str(audit.id),
        str(domain.id),
    )

    return audit


@router.get("", response_model=List[AuditSummary])
async def list_audits(
    domain_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List all audits"""
    query = (
        select(Audit, Domain.domain_name)
        .join(Domain, Audit.domain_id == Domain.id)
        .order_by(Audit.created_at.desc())
    )

    if domain_id:
        query = query.where(Audit.domain_id == str(domain_id))

    result = await db.execute(query)
    audits = []
    for audit, domain_name in result.all():
        audits.append(
            AuditSummary(
                id=audit.id,
                domain_id=audit.domain_id,
                domain_name=domain_name,
                status=audit.status,
                overall_score=audit.overall_score,
                created_at=audit.created_at,
                completed_at=audit.completed_at,
            )
        )
    return audits


@router.get("/{audit_id}", response_model=AuditResponse)
async def get_audit(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific audit with all results"""
    result = await db.execute(
        select(Audit).where(Audit.id == str(audit_id))
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit not found",
        )

    # Load all related data
    await db.refresh(audit, ["results", "tls_result", "header_result", "cookie_results", "robots_result", "security_txt_result", "server_info_result"])

    return audit


@router.delete("/{audit_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_audit(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete an audit"""
    result = await db.execute(
        select(Audit).where(Audit.id == str(audit_id))
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit not found",
        )
    await db.delete(audit)
    await db.commit()
    return None