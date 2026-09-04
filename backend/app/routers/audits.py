import asyncio
import threading
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from uuid import UUID

from ..database import get_db
from ..schemas.audit import AuditCreate, AuditResponse, AuditSummary
from ..services.audit_engine import AuditEngine
from ..models.audit import Audit, AuditResult, TLSResult, HeaderResult, CookieResult, RobotsResult, SecurityTxtResult, ServerInfoResult
from ..models.domain import Domain
from ..models.user import User


router = APIRouter()


async def _get_default_user_id(db: AsyncSession) -> str:
    """Get the default user ID for no-auth mode"""
    result = await db.execute(
        select(User.id).where(User.email == "default@securesite-audit.local")
    )
    user_id = result.scalar_one_or_none()
    if not user_id:
        # Pre-computed bcrypt hash for "default123"
        DEFAULT_PASSWORD_HASH = "$2b$12$Wx6iC9nsN8ifjX7DU4XfNek/qK69aod20W634VcKnwT93is9PP.bq"
        default_user = User(
            email="default@securesite-audit.local",
            hashed_password=DEFAULT_PASSWORD_HASH,
            full_name="Default User",
            is_active=True,
            is_verified=True,
        )
        db.add(default_user)
        await db.commit()
        await db.refresh(default_user)
        return default_user.id
    return user_id


def _run_audit_background_sync(audit_id: str, domain_id: str):
    """Synchronous wrapper to run async audit in background thread"""
    def run_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_audit_background(audit_id, domain_id))
        finally:
            loop.close()
    
    thread = threading.Thread(target=run_async)
    thread.start()


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

    # Get default user ID
    user_id = await _get_default_user_id(db)

    # Create audit
    audit = Audit(
        user_id=user_id,
        domain_id=str(audit_data.domain_id),
        status="pending",
    )
    db.add(audit)
    await db.commit()
    await db.refresh(audit)

    # Run audit in background (use sync wrapper for BackgroundTasks)
    background_tasks.add_task(
        _run_audit_background_sync,
        str(audit.id),
        str(domain.id),
    )

    # Re-query with relationships eagerly loaded to avoid lazy loading issues
    result = await db.execute(
        select(Audit)
        .options(
            selectinload(Audit.results),
            selectinload(Audit.tls_result),
            selectinload(Audit.header_result),
            selectinload(Audit.cookie_results),
            selectinload(Audit.robots_result),
            selectinload(Audit.security_txt_result),
            selectinload(Audit.server_info_result),
            selectinload(Audit.sslabs_result),
            selectinload(Audit.dns_result),
            selectinload(Audit.cors_result),
            selectinload(Audit.clickjacking_result),
        )
        .where(Audit.id == audit.id)
    )
    audit = result.scalar_one()
    return audit


@router.get("", response_model=List[AuditSummary])
async def list_audits(
    domain_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List all audits"""
    user_id = await _get_default_user_id(db)
    query = (
        select(Audit, Domain.domain_name)
        .join(Domain, Audit.domain_id == Domain.id)
        .where(Audit.user_id == user_id)
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
    user_id = await _get_default_user_id(db)
    result = await db.execute(
        select(Audit)
        .options(
            selectinload(Audit.results),
            selectinload(Audit.tls_result),
            selectinload(Audit.header_result),
            selectinload(Audit.cookie_results),
            selectinload(Audit.robots_result),
            selectinload(Audit.security_txt_result),
            selectinload(Audit.server_info_result),
            selectinload(Audit.sslabs_result),
            selectinload(Audit.dns_result),
            selectinload(Audit.cors_result),
            selectinload(Audit.clickjacking_result),
        )
        .where(Audit.id == str(audit_id), Audit.user_id == user_id)
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit not found",
        )

    return audit


@router.delete("/{audit_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_audit(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete an audit"""
    user_id = await _get_default_user_id(db)
    result = await db.execute(
        select(Audit).where(Audit.id == str(audit_id), Audit.user_id == user_id)
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