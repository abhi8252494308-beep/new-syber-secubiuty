from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID

from ..database import get_db
from ..schemas.domain import DomainCreate, DomainResponse, DomainVerificationResponse
from ..services.domain_verification import DomainVerificationService

router = APIRouter()


@router.post("", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def add_domain(
    domain_data: DomainCreate,
    db: AsyncSession = Depends(get_db),
):
    """Add a new domain for verification"""
    domain = await DomainVerificationService.create_domain(
        db, domain_data.domain_name, domain_data.verification_method
    )
    return domain


@router.get("", response_model=List[DomainResponse])
async def list_domains(
    db: AsyncSession = Depends(get_db),
):
    """List all domains"""
    domains = await DomainVerificationService.get_all_domains(db)
    return domains


@router.get("/{domain_id}", response_model=DomainResponse)
async def get_domain(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific domain"""
    domain = await DomainVerificationService.get_domain_by_id(db, UUID(domain_id))
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    return domain


@router.post("/{domain_id}/verify", response_model=DomainVerificationResponse)
async def verify_domain(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Verify domain ownership"""
    success, message = await DomainVerificationService.verify_domain(
        db, UUID(domain_id)
    )
    return DomainVerificationResponse(success=success, message=message)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(
    domain_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a domain"""
    success = await DomainVerificationService.delete_domain(db, UUID(domain_id))
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    return None