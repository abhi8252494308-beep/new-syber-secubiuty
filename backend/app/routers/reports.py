from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from uuid import UUID
import os

from ..database import get_db
from ..services.pdf_report import PDFReportService
from ..models.audit import PDFReport, Audit
from ..models.domain import Domain
from ..models.user import User


router = APIRouter()
pdf_service = PDFReportService()


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


@router.post("/generate/{audit_id}")
async def generate_report(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Generate a PDF report for an audit"""
    user_id = await _get_default_user_id(db)
    # Verify audit exists and belongs to user
    result = await db.execute(
        select(Audit).where(Audit.id == str(audit_id), Audit.user_id == user_id)
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit not found",
        )

    if audit.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Audit is not completed yet",
        )

    # Generate report
    pdf_report = await pdf_service.generate_report(db, str(audit_id), user_id)
    if not pdf_report:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate report",
        )

    return {
        "message": "Report generated successfully",
        "report_id": str(pdf_report.id),
        "file_size": pdf_report.file_size,
    }


@router.get("/download/{report_id}")
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Download a PDF report"""
    pdf_report = await pdf_service.get_report(db, str(report_id))
    if not pdf_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )

    if not os.path.exists(pdf_report.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found",
        )

    # Update download count
    pdf_report.download_count += 1
    await db.commit()

    media_type = "application/pdf" if pdf_report.file_path.endswith(".pdf") else "text/plain"
    filename = os.path.basename(pdf_report.file_path)

    return FileResponse(
        path=pdf_report.file_path,
        filename=filename,
        media_type=media_type,
    )


@router.get("", response_model=list)
async def list_reports(
    db: AsyncSession = Depends(get_db),
):
    """List all PDF reports"""
    user_id = await _get_default_user_id(db)
    reports = await pdf_service.get_all_reports(db, user_id)
    result_list = []
    for r in reports:
        audit_res = await db.execute(select(Audit).where(Audit.id == str(r.audit_id), Audit.user_id == user_id))
        audit = audit_res.scalar_one_or_none()
        domain_name = "Unknown"
        if audit:
            domain_res = await db.execute(select(Domain).where(Domain.id == str(audit.domain_id), Domain.user_id == user_id))
            domain = domain_res.scalar_one_or_none()
            if domain:
                domain_name = domain.domain_name
        result_list.append({
            "id": str(r.id),
            "audit_id": str(r.audit_id),
            "domain_name": domain_name,
            "file_size": r.file_size,
            "generated_at": r.generated_at.isoformat() if r.generated_at else None,
            "download_count": r.download_count,
        })
    return result_list


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a PDF report"""
    user_id = await _get_default_user_id(db)
    pdf_report = await pdf_service.get_report(db, str(report_id), user_id)
    if not pdf_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )

    # Delete file
    if os.path.exists(pdf_report.file_path):
        try:
            os.remove(pdf_report.file_path)
        except OSError:
            pass

    # Delete record
    await db.delete(pdf_report)
    await db.commit()
    return None