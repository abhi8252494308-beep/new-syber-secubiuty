from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from uuid import UUID
import os

from app.database import get_db
from app.services.pdf_report import PDFReportService
from app.models.audit import PDFReport, Audit
from app.models.domain import Domain

router = APIRouter()
pdf_service = PDFReportService()


@router.post("/generate/{audit_id}")
async def generate_report(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Generate a PDF report for an audit"""
    # Verify audit exists
    result = await db.execute(
        select(Audit).where(Audit.id == str(audit_id))
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
    pdf_report = await pdf_service.generate_report(db, str(audit_id))
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
    reports = await pdf_service.get_all_reports(db)
    result_list = []
    for r in reports:
        audit_res = await db.execute(select(Audit).where(Audit.id == str(r.audit_id)))
        audit = audit_res.scalar_one_or_none()
        domain_name = "Unknown"
        if audit:
            domain_res = await db.execute(select(Domain).where(Domain.id == str(audit.domain_id)))
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
    pdf_report = await pdf_service.get_report(db, str(report_id))
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