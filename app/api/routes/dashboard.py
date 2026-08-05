"""
Purpose: Dashboard REST API router providing security analytics endpoints.

Responsibilities:
- Expose /api/dashboard, /api/repositories, /api/scans, /api/findings, /api/events.
- Support search, severity filters, scanner filters, and pagination.

Dependencies:
- fastapi.APIRouter, Depends, Query, HTTPException, status
- sqlalchemy.orm.Session
- app.db.session.get_db
- app.db.repository.DatabaseRepository
- app.db.models.RepositoryModel, ScanModel, FindingModel, EventModel
- app.schemas.dashboard.*

Usage:
    Included in main FastAPI application router.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models import EventModel, FindingModel, RepositoryModel, ScanModel
from app.db.repository import DatabaseRepository
from app.db.session import get_db
from app.schemas.dashboard import (
    DashboardOverviewResponse,
    EventResponse,
    FindingResponse,
    RepositoryResponse,
    ScanDetailResponse,
)

router = APIRouter(prefix="/api", tags=["Web Dashboard APIs"])


@router.get(
    "/dashboard",
    response_model=DashboardOverviewResponse,
    summary="Dashboard Overview Metrics",
    description="Returns high-level metric cards, severity distribution counts, and recent activity logs.",
)
def get_dashboard_overview(db: Session = Depends(get_db)) -> DashboardOverviewResponse:
    """Get aggregated dashboard metrics."""
    dao = DatabaseRepository(db)
    stats = dao.get_dashboard_overview()
    return DashboardOverviewResponse(**stats)


@router.get(
    "/repositories",
    response_model=List[RepositoryResponse],
    summary="List Scanned Repositories",
    description="Returns list of all scanned repositories with risk score calculation.",
)
def get_repositories(db: Session = Depends(get_db)) -> List[RepositoryResponse]:
    """Get repositories with risk score."""
    repos = db.execute(select(RepositoryModel)).scalars().all()
    result = []
    for r in repos:
        total_scans = len(r.scans)
        open_findings = sum(
            len([f for f in s.findings if f.status == "open"])
            for s in r.scans
        )
        # Calculate Risk Score formula (Critical=10, High=5, Med=2, Low=1)
        risk_score = 0.0
        for s in r.scans:
            for f in s.findings:
                if f.severity == "CRITICAL":
                    risk_score += 10.0
                elif f.severity == "HIGH":
                    risk_score += 5.0
                elif f.severity == "MEDIUM":
                    risk_score += 2.0
                else:
                    risk_score += 1.0

        result.append(
            RepositoryResponse(
                id=r.id,
                owner=r.owner,
                name=r.name,
                full_name=f"{r.owner}/{r.name}",
                default_branch=r.default_branch,
                created_at=r.created_at,
                risk_score=min(risk_score, 100.0),
                total_scans=total_scans,
                open_findings=open_findings,
            )
        )
    return result


@router.get(
    "/repositories/{repo_id}",
    response_model=RepositoryResponse,
    summary="Get Single Repository Details",
)
def get_repository_by_id(repo_id: int, db: Session = Depends(get_db)) -> RepositoryResponse:
    """Get repository by ID."""
    r = db.execute(select(RepositoryModel).where(RepositoryModel.id == repo_id)).scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    total_scans = len(r.scans)
    open_findings = sum(len([f for f in s.findings if f.status == "open"]) for s in r.scans)
    risk_score = 0.0
    for s in r.scans:
        for f in s.findings:
            sev = f.severity.upper()
            if sev == "CRITICAL":
                risk_score += 10.0
            elif sev == "HIGH":
                risk_score += 5.0
            elif sev == "MEDIUM":
                risk_score += 2.0
            else:
                risk_score += 1.0

    return RepositoryResponse(
        id=r.id,
        owner=r.owner,
        name=r.name,
        full_name=f"{r.owner}/{r.name}",
        default_branch=r.default_branch,
        created_at=r.created_at,
        risk_score=min(risk_score, 100.0),
        total_scans=total_scans,
        open_findings=open_findings,
    )


@router.get(
    "/scans",
    response_model=List[ScanDetailResponse],
    summary="List Scan History",
)
def get_scans(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> List[ScanDetailResponse]:
    """Get scan history list."""
    scans = db.execute(select(ScanModel).order_by(desc(ScanModel.started_at)).limit(limit)).scalars().all()
    res = []
    for s in scans:
        findings_resp = [
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                scanner=f.scanner,
                severity=f.severity,
                title=f.title,
                description=f.description,
                file=f.file,
                line=f.line,
                rule=f.rule,
                recommendation=f.recommendation,
                cwe=f.cwe,
                owasp=f.owasp,
                cvss=f.cvss,
                status=f.status,
            )
            for f in s.findings
        ]
        res.append(
            ScanDetailResponse(
                id=s.id,
                repository_id=s.repository_id,
                repository_name=f"{s.repository.owner}/{s.repository.name}" if s.repository else "unknown",
                commit_sha=s.commit_sha,
                branch=s.branch,
                trigger=s.trigger,
                status=s.status,
                started_at=s.started_at,
                finished_at=s.finished_at,
                duration=s.duration,
                total_findings=len(s.findings),
                findings=findings_resp,
            )
        )
    return res


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get Scan Details",
)
def get_scan_by_id(scan_id: str, db: Session = Depends(get_db)) -> ScanDetailResponse:
    """Get single scan details by ID."""
    s = db.execute(select(ScanModel).where(ScanModel.id == scan_id)).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    findings_resp = [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            scanner=f.scanner,
            severity=f.severity,
            title=f.title,
            description=f.description,
            file=f.file,
            line=f.line,
            rule=f.rule,
            recommendation=f.recommendation,
            cwe=f.cwe,
            owasp=f.owasp,
            cvss=f.cvss,
            status=f.status,
        )
        for f in s.findings
    ]
    return ScanDetailResponse(
        id=s.id,
        repository_id=s.repository_id,
        repository_name=f"{s.repository.owner}/{s.repository.name}" if s.repository else "unknown",
        commit_sha=s.commit_sha,
        branch=s.branch,
        trigger=s.trigger,
        status=s.status,
        started_at=s.started_at,
        finished_at=s.finished_at,
        duration=s.duration,
        total_findings=len(s.findings),
        findings=findings_resp,
    )


@router.get(
    "/findings",
    response_model=List[FindingResponse],
    summary="List Security Findings with Filters",
)
def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    scanner: Optional[str] = Query(None, description="Filter by scanner: Gitleaks, Semgrep"),
    status: Optional[str] = Query(None, description="Filter by status: open, resolved"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> List[FindingResponse]:
    """Get filterable security findings."""
    stmt = select(FindingModel)
    if severity:
        stmt = stmt.where(FindingModel.severity == severity.upper())
    if scanner:
        stmt = stmt.where(FindingModel.scanner == scanner)
    if status:
        stmt = stmt.where(FindingModel.status == status)

    stmt = stmt.limit(limit)
    findings = db.execute(stmt).scalars().all()

    return [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            scanner=f.scanner,
            severity=f.severity,
            title=f.title,
            description=f.description,
            file=f.file,
            line=f.line,
            rule=f.rule,
            recommendation=f.recommendation,
            cwe=f.cwe,
            owasp=f.owasp,
            cvss=f.cvss,
            status=f.status,
        )
        for f in findings
    ]


@router.get(
    "/events",
    response_model=List[EventResponse],
    summary="List Webhook Events Audit Log",
)
def get_events(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> List[EventResponse]:
    """Get webhook delivery event audit log."""
    events = db.execute(select(EventModel).order_by(desc(EventModel.created_at)).limit(limit)).scalars().all()
    return [
        EventResponse(
            id=e.id,
            repository_id=e.repository_id,
            event=e.event,
            delivery_id=e.delivery_id,
            created_at=e.created_at,
        )
        for e in events
    ]
