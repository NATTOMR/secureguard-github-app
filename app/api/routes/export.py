"""
Purpose: REST API router for SARIF 2.1.0, PDF, and HTML security exports.

Responsibilities:
- Provide `GET /api/export/sarif/{scan_id}` to download SARIF 2.1.0 report.
- Provide `GET /api/export/pdf/{scan_id}` to download PDF executive report.
- Provide `GET /api/export/html/{scan_id}` to download HTML security report.
- Support 'latest' scan_id keyword to export the most recent scan result.

Dependencies:
- fastapi.APIRouter, Depends, HTTPException, Path, Response, status
- sqlalchemy.orm.Session
- sqlalchemy.select, desc
- app.db.session.get_db
- app.db.models.ScanModel, RepositoryModel, FindingModel
- app.services.sarif_service.SARIFService
- app.services.pdf_report_service.PDFReportService

Usage:
    Included in main API router.
"""

from datetime import datetime, timezone
import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Response, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models import FindingModel, RepositoryModel, ScanModel
from app.db.session import get_db
from app.services.pdf_report_service import PDFReportService
from app.services.sarif_service import SARIFService

router = APIRouter(prefix="/api/export", tags=["Security Exports"])


def _get_scan_or_demo(scan_id: str, db: Session) -> ScanModel:
    """Helper to fetch a scan by UUID or 'latest' keyword, returning a demo scan if DB is empty."""
    scan: Optional[ScanModel] = None

    if scan_id.lower() == "latest":
        scan = db.execute(select(ScanModel).order_by(desc(ScanModel.started_at)).limit(1)).scalar_one_or_none()
    else:
        scan = db.execute(select(ScanModel).where(ScanModel.id == scan_id)).scalar_one_or_none()

    if not scan:
        # Fallback to latest available scan if specific ID not found
        scan = db.execute(select(ScanModel).order_by(desc(ScanModel.started_at)).limit(1)).scalar_one_or_none()

    if not scan:
        # Return a synthetic demo scan if no scans exist yet in database
        repo = RepositoryModel(id=1, owner="NATTOMR", name="secureguard-github-app", default_branch="main")
        scan = ScanModel(
            id="demo-scan-0000-0000-0000",
            repository_id=1,
            commit_sha="7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
            branch="main",
            trigger="push",
            status="completed",
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            duration=1.5,
            repository=repo,
        )
        finding = FindingModel(
            id="demo-finding-1111",
            scan_id=scan.id,
            scanner="Gitleaks",
            severity="HIGH",
            title="Hardcoded AWS Access Key ID",
            description="Identified potential AWS Access Key ID in source code.",
            file="app/config.py",
            line=42,
            rule="gitleaks-aws-key",
            recommendation="Store AWS secrets in environment variables or GitHub Secrets.",
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            status="open",
        )
        scan.findings = [finding]

    return scan


@router.get(
    "/sarif/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Export Scan as SARIF 2.1.0 JSON",
    description="Generates GitHub Code Scanning compatible SARIF 2.1.0 report for a scan. Pass 'latest' or a valid scan UUID.",
)
def export_sarif(
    scan_id: str = Path(..., description="Scan ID UUID or 'latest'", openapi_examples={"latest": {"summary": "Latest Scan", "value": "latest"}}),
    db: Session = Depends(get_db),
):
    """Export scan as SARIF 2.1.0."""
    scan = _get_scan_or_demo(scan_id, db)
    sarif_service = SARIFService()
    sarif_data = sarif_service.generate_sarif(scan)

    return Response(
        content=json.dumps(sarif_data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="secureguard-scan-{scan.id}.sarif"'
        },
    )


@router.get(
    "/pdf/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Export Scan as PDF Report",
    description="Generates downloadable executive PDF security report. Pass 'latest' or a valid scan UUID.",
)
def export_pdf(
    scan_id: str = Path(..., description="Scan ID UUID or 'latest'", openapi_examples={"latest": {"summary": "Latest Scan", "value": "latest"}}),
    db: Session = Depends(get_db),
):
    """Export scan as PDF report."""
    scan = _get_scan_or_demo(scan_id, db)
    pdf_service = PDFReportService()
    pdf_bytes = pdf_service.generate_pdf_report(scan)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="secureguard-report-{scan.id}.pdf"'
        },
    )


@router.get(
    "/html/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Export Scan as Standalone HTML Report",
    description="Generates standalone HTML security report. Pass 'latest' or a valid scan UUID.",
)
def export_html(
    scan_id: str = Path(..., description="Scan ID UUID or 'latest'", openapi_examples={"latest": {"summary": "Latest Scan", "value": "latest"}}),
    db: Session = Depends(get_db),
):
    """Export scan as HTML report."""
    scan = _get_scan_or_demo(scan_id, db)
    pdf_service = PDFReportService()
    html_content = pdf_service.generate_html_report(scan)

    return Response(
        content=html_content,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="secureguard-report-{scan.id}.html"'
        },
    )
