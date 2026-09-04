import os
from datetime import datetime
from typing import Optional, Any
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jinja2 import Template

from ..config import settings
from ..models.audit import Audit, AuditResult, TLSResult, HeaderResult, CookieResult, RobotsResult, SecurityTxtResult, ServerInfoResult, PDFReport
from ..models.domain import Domain
from ..models.user import User


class PDFReportService:
    def __init__(self):
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    async def generate_report(self, db: AsyncSession, audit_id: Any, user_id: str) -> Optional[PDFReport]:
        """Generate a PDF report for an audit"""
        # Get audit with all related data
        result = await db.execute(
            select(Audit).where(Audit.id == str(audit_id), Audit.user_id == user_id)
        )
        audit = result.scalar_one_or_none()
        if not audit or audit.status != "completed":
            return None

        # Get domain info
        result = await db.execute(
            select(Domain).where(Domain.id == str(audit.domain_id), Domain.user_id == user_id)
        )
        domain = result.scalar_one_or_none()
        if not domain:
            return None

        # Get all audit results
        result = await db.execute(
            select(AuditResult).where(AuditResult.audit_id == str(audit_id))
        )
        audit_results = result.scalars().all()

        # Get TLS results
        result = await db.execute(
            select(TLSResult).where(TLSResult.audit_id == str(audit_id))
        )
        tls_result = result.scalar_one_or_none()

        # Get header results
        result = await db.execute(
            select(HeaderResult).where(HeaderResult.audit_id == str(audit_id))
        )
        header_result = result.scalar_one_or_none()

        # Get cookie results
        result = await db.execute(
            select(CookieResult).where(CookieResult.audit_id == str(audit_id))
        )
        cookie_results = result.scalars().all()

        # Get robots results
        result = await db.execute(
            select(RobotsResult).where(RobotsResult.audit_id == str(audit_id))
        )
        robots_result = result.scalar_one_or_none()

        # Get security.txt results
        result = await db.execute(
            select(SecurityTxtResult).where(SecurityTxtResult.audit_id == str(audit_id))
        )
        security_txt_result = result.scalar_one_or_none()

        # Get server info results
        result = await db.execute(
            select(ServerInfoResult).where(ServerInfoResult.audit_id == str(audit_id))
        )
        server_info_result = result.scalar_one_or_none()

        # Generate PDF using ReportLab
        try:
            filename = f"audit_report_{audit_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = os.path.join(self.reports_dir, filename)
            self._generate_reportlab_pdf(
                filepath=filepath,
                domain=domain,
                audit=audit,
                audit_results=audit_results,
                tls_result=tls_result,
                header_result=header_result,
                cookie_results=cookie_results,
                robots_result=robots_result,
                security_txt_result=security_txt_result,
                server_info_result=server_info_result,
            )

            file_size = os.path.getsize(filepath)
            pdf_report = PDFReport(
                user_id=user_id,
                audit_id=str(audit_id),
                file_path=filepath,
                file_size=file_size,
            )
            db.add(pdf_report)
            await db.commit()
            await db.refresh(pdf_report)
            return pdf_report

        except Exception as rl_err:
            print(f"ReportLab PDF generation error: {rl_err}")
            # Fallback to HTML/WeasyPrint if available or text-based report
            try:
                from weasyprint import HTML
                html_content = self._generate_html(
                    domain=domain,
                    audit=audit,
                    audit_results=audit_results,
                    tls_result=tls_result,
                    header_result=header_result,
                    cookie_results=cookie_results,
                    robots_result=robots_result,
                    security_txt_result=security_txt_result,
                    server_info_result=server_info_result,
                )
                filename = f"audit_report_{audit_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
                filepath = os.path.join(self.reports_dir, filename)
                HTML(string=html_content).write_pdf(filepath)

                file_size = os.path.getsize(filepath)
                pdf_report = PDFReport(
                    user_id=user_id,
                    audit_id=str(audit_id),
                    file_path=filepath,
                    file_size=file_size,
                )
                db.add(pdf_report)
                await db.commit()
                await db.refresh(pdf_report)
                return pdf_report
            except Exception:
                return await self._generate_text_report(db, str(audit_id), domain, audit, audit_results, user_id)

    def _generate_reportlab_pdf(
        self,
        filepath: str,
        domain: Domain,
        audit: Audit,
        audit_results: list,
        tls_result: Optional[TLSResult],
        header_result: Optional[HeaderResult],
        cookie_results: list,
        robots_result: Optional[RobotsResult],
        security_txt_result: Optional[SecurityTxtResult],
        server_info_result: Optional[ServerInfoResult],
    ):
        """Generate PDF using reportlab"""
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            'ReportSubTitle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#4b5563'),
        )
        h2_style = ParagraphStyle(
            'Heading2',
            parent=styles['Heading2'],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor('#1f2937'),
            spaceBefore=10,
            spaceAfter=5,
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#374151'),
        )
        body_bold = ParagraphStyle(
            'BodyBold',
            parent=body_style,
            fontName='Helvetica-Bold',
        )

        elements = []

        # Title & Header
        score_val = audit.overall_score if audit.overall_score is not None else 0
        score_color = colors.HexColor('#16a34a') if score_val >= 80 else (colors.HexColor('#d97706') if score_val >= 50 else colors.HexColor('#dc2626'))

        header_data = [
            [
                Paragraph(f"<b>SecureSite Audit Report</b>", title_style),
                Paragraph(f"<b>Score: {score_val}/100</b>", ParagraphStyle('Score', parent=title_style, fontSize=18, textColor=score_color, alignment=2)),
            ],
            [
                Paragraph(f"Website: <b>{domain.domain_name}</b> | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style),
                Paragraph(f"Status: <b>{audit.status.upper()}</b>", ParagraphStyle('Status', parent=subtitle_style, alignment=2)),
            ]
        ]
        header_table = Table(header_data, colWidths=[380, 160])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 6))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceAfter=10))

        # Overview Table
        elements.append(Paragraph("Audit Overview", h2_style))
        overview_data = [
            [Paragraph("<b>Target Domain</b>", body_bold), Paragraph(str(domain.domain_name), body_style)],
            [Paragraph("<b>Audit Date</b>", body_bold), Paragraph(str(audit.completed_at or audit.created_at), body_style)],
            [Paragraph("<b>Verification Method</b>", body_bold), Paragraph(str(domain.verification_method).upper(), body_style)],
            [Paragraph("<b>Overall Security Score</b>", body_bold), Paragraph(f"{score_val} / 100", body_style)],
        ]
        overview_table = Table(overview_data, colWidths=[150, 390])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(overview_table)
        elements.append(Spacer(1, 8))

        # Check Results Table
        elements.append(Paragraph("Security Checks Summary", h2_style))
        results_rows = [
            [
                Paragraph("<b>Check</b>", body_bold),
                Paragraph("<b>Status</b>", body_bold),
                Paragraph("<b>Score</b>", body_bold),
                Paragraph("<b>Key Recommendations / Findings</b>", body_bold),
            ]
        ]

        for res in audit_results:
            st = res.status.upper()
            st_color = '#16a34a' if st == 'PASS' else '#dc2626'
            recs_text = ", ".join(res.recommendations) if res.recommendations else "All checks passed cleanly."
            results_rows.append([
                Paragraph(f"<b>{res.check_name}</b>", body_style),
                Paragraph(f"<font color='{st_color}'><b>{st}</b></font>", body_style),
                Paragraph(f"{res.score}/{res.max_score}", body_style),
                Paragraph(recs_text[:180] + ('...' if len(recs_text) > 180 else ''), body_style),
            ])

        res_table = Table(results_rows, colWidths=[140, 55, 55, 290])
        res_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#eff6ff')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(res_table)
        elements.append(Spacer(1, 10))

        # TLS Details if present
        if tls_result:
            elements.append(Paragraph("HTTPS / TLS Details", h2_style))
            tls_data = [
                [Paragraph("<b>HTTPS Enabled</b>", body_bold), Paragraph("Yes" if tls_result.has_https else "No", body_style)],
                [Paragraph("<b>TLS Version</b>", body_bold), Paragraph(str(tls_result.tls_version or "N/A"), body_style)],
                [Paragraph("<b>Cipher Suite</b>", body_bold), Paragraph(str(tls_result.cipher_suite or "N/A"), body_style)],
                [Paragraph("<b>Certificate Valid</b>", body_bold), Paragraph("Yes" if tls_result.certificate_valid else "No", body_style)],
                [Paragraph("<b>Certificate Issuer</b>", body_bold), Paragraph(str(tls_result.certificate_issuer or "N/A"), body_style)],
                [Paragraph("<b>Days Remaining</b>", body_bold), Paragraph(str(tls_result.certificate_days_remaining or "N/A"), body_style)],
                [Paragraph("<b>HSTS Enabled</b>", body_bold), Paragraph("Yes" if tls_result.hsts_enabled else "No", body_style)],
            ]
            tls_table = Table(tls_data, colWidths=[150, 390])
            tls_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(tls_table)
            elements.append(Spacer(1, 8))

        # Security Headers if present
        if header_result:
            elements.append(Paragraph("Security Headers", h2_style))
            h_data = [
                [Paragraph("<b>Content-Security-Policy</b>", body_bold), Paragraph(str(header_result.content_security_policy or "Not Configured"), body_style)],
                [Paragraph("<b>X-Frame-Options</b>", body_bold), Paragraph(str(header_result.x_frame_options or "Not Configured"), body_style)],
                [Paragraph("<b>X-Content-Type-Options</b>", body_bold), Paragraph(str(header_result.x_content_type_options or "Not Configured"), body_style)],
                [Paragraph("<b>Strict-Transport-Security</b>", body_bold), Paragraph(str(header_result.strict_transport_security or "Not Configured"), body_style)],
                [Paragraph("<b>Referrer-Policy</b>", body_bold), Paragraph(str(header_result.referrer_policy or "Not Configured"), body_style)],
            ]
            h_table = Table(h_data, colWidths=[170, 370])
            h_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(h_table)
            elements.append(Spacer(1, 10))

        # Footer
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#9ca3af'), spaceAfter=5))
        elements.append(Paragraph("Generated automatically by SecureSite Audit Platform. Defensive audit.", subtitle_style))

        doc.build(elements)

    async def _generate_text_report(self, db, audit_id, domain, audit, audit_results, user_id: str):
        """Fallback text-based report generation"""
        filename = f"audit_report_{audit_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"SecureSite Audit Report\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"Domain: {domain.domain_name}\n")
            f.write(f"Audit Date: {audit.completed_at}\n")
            f.write(f"Overall Score: {audit.overall_score}/100\n\n")
            f.write(f"Results:\n")
            f.write(f"{'-' * 50}\n")
            for result in audit_results:
                f.write(f"\n{result.check_name}: {result.status.upper()}\n")
                f.write(f"Score: {result.score}/{result.max_score}\n")
                if result.recommendations:
                    f.write("Recommendations:\n")
                    for rec in result.recommendations:
                        f.write(f"  - {rec}\n")

        file_size = os.path.getsize(filepath)
        pdf_report = PDFReport(
            user_id=user_id,
            audit_id=str(audit_id),
            file_path=filepath,
            file_size=file_size,
        )
        db.add(pdf_report)
        await db.commit()
        await db.refresh(pdf_report)
        return pdf_report

    def _generate_html(
        self,
        domain: Domain,
        audit: Audit,
        audit_results: list,
        tls_result: Optional[TLSResult],
        header_result: Optional[HeaderResult],
        cookie_results: list,
        robots_result: Optional[RobotsResult],
        security_txt_result: Optional[SecurityTxtResult],
        server_info_result: Optional[ServerInfoResult],
    ) -> str:
        """Generate HTML content for PDF report"""
        template = Template(HTML_TEMPLATE)
        return template.render(
            domain=domain,
            audit=audit,
            audit_results=audit_results,
            tls_result=tls_result,
            header_result=header_result,
            cookie_results=cookie_results,
            robots_result=robots_result,
            security_txt_result=security_txt_result,
            server_info_result=server_info_result,
            generated_at=datetime.utcnow(),
        )

    async def get_report(self, db: AsyncSession, report_id: Any, user_id: str) -> Optional[PDFReport]:
        """Get a PDF report by ID"""
        result = await db.execute(
            select(PDFReport).where(PDFReport.id == str(report_id), PDFReport.user_id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_all_reports(self, db: AsyncSession, user_id: str):
        """Get all PDF reports"""
        result = await db.execute(
            select(PDFReport).where(PDFReport.user_id == user_id).order_by(PDFReport.created_at.desc())
        )
        return result.scalars().all()


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SecureSite Audit Report - {{ domain.domain_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
        h1 { color: #1a73e8; border-bottom: 2px solid #1a73e8; padding-bottom: 10px; }
        h2 { color: #202124; margin-top: 30px; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .score { font-size: 48px; font-weight: bold; }
        .score-good { color: #0d904f; }
        .score-medium { color: #f4b400; }
        .score-bad { color: #db4437; }
        .info-box { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .result-item { border: 1px solid #e0e0e0; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .result-pass { border-left: 4px solid #0d904f; }
        .result-fail { border-left: 4px solid #db4437; }
        .result-warn { border-left: 4px solid #f4b400; }
        .recommendations { background: #fff3e0; padding: 10px; border-radius: 5px; margin-top: 10px; }
        .recommendations ul { margin: 5px 0; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #e0e0e0; }
        th { background: #f8f9fa; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SecureSite Audit Report</h1>
        <div class="score {% if audit.overall_score >= 80 %}score-good{% elif audit.overall_score >= 50 %}score-medium{% else %}score-bad{% endif %}">
            {{ audit.overall_score }}/100
        </div>
    </div>

    <div class="info-box">
        <p><strong>Domain:</strong> {{ domain.domain_name }}</p>
        <p><strong>Audit Date:</strong> {{ audit.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if audit.completed_at else 'N/A' }}</p>
        <p><strong>Report Generated:</strong> {{ generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
    </div>

    <h2>Executive Summary</h2>
    <p>This report contains the results of a security audit performed on <strong>{{ domain.domain_name }}</strong>.
    The audit checked for HTTPS/TLS configuration, security headers, cookie security, and other security best practices.</p>

    <h2>Detailed Results</h2>

    {% for result in audit_results %}
    <div class="result-item result-{{ result.status }}">
        <h3>{{ result.check_name }}</h3>
        <p><strong>Status:</strong> {{ result.status.upper() }} | <strong>Score:</strong> {{ result.score }}/{{ result.max_score }}</p>

        {% if result.details %}
        <table>
            {% for key, value in result.details.items() %}
            <tr>
                <th>{{ key.replace('_', ' ').title() }}</th>
                <td>{{ value if value is not none else 'N/A' }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if result.recommendations %}
        <div class="recommendations">
            <strong>Recommendations:</strong>
            <ul>
                {% for rec in result.recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
    </div>
    {% endfor %}

    {% if tls_result %}
    <h2>TLS/Certificate Details</h2>
    <div class="info-box">
        <table>
            <tr><th>HTTPS Enabled</th><td>{{ 'Yes' if tls_result.has_https else 'No' }}</td></tr>
            <tr><th>TLS Version</th><td>{{ tls_result.tls_version or 'N/A' }}</td></tr>
            <tr><th>Cipher Suite</th><td>{{ tls_result.cipher_suite or 'N/A' }}</td></tr>
            <tr><th>Certificate Valid</th><td>{{ 'Yes' if tls_result.certificate_valid else 'No' }}</td></tr>
            <tr><th>Issuer</th><td>{{ tls_result.certificate_issuer or 'N/A' }}</td></tr>
            <tr><th>Expires</th><td>{{ tls_result.certificate_not_after.strftime('%Y-%m-%d') if tls_result.certificate_not_after else 'N/A' }}</td></tr>
            <tr><th>Days Remaining</th><td>{{ tls_result.certificate_days_remaining or 'N/A' }}</td></tr>
            <tr><th>HSTS Enabled</th><td>{{ 'Yes' if tls_result.hsts_enabled else 'No' }}</td></tr>
        </table>
    </div>
    {% endif %}

    {% if header_result %}
    <h2>Security Headers</h2>
    <div class="info-box">
        <table>
            <tr><th>Content Security Policy</th><td>{{ header_result.content_security_policy or 'Not set' }}</td></tr>
            <tr><th>X-Frame-Options</th><td>{{ header_result.x_frame_options or 'Not set' }}</td></tr>
            <tr><th>X-Content-Type-Options</th><td>{{ header_result.x_content_type_options or 'Not set' }}</td></tr>
            <tr><th>X-XSS-Protection</th><td>{{ header_result.x_xss_protection or 'Not set' }}</td></tr>
            <tr><th>Referrer-Policy</th><td>{{ header_result.referrer_policy or 'Not set' }}</td></tr>
            <tr><th>Permissions-Policy</th><td>{{ header_result.permissions_policy or 'Not set' }}</td></tr>
        </table>
    </div>
    {% endif %}

    <div class="footer">
        <p>This report was generated by SecureSite Audit. The checks performed are non-intrusive and focus on publicly available information.</p>
        <p>For questions or support, please contact support@securesite-audit.com</p>
    </div>
</body>
</html>
"""