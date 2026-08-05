"""
Purpose: REST API router for Enterprise Repository Discovery.

Responsibilities:
- Provide `GET /api/repositories` with pagination and filtering (search, language, visibility, archived).
- Provide `GET /api/repositories/{owner}/{repo}` with full repository details, latest scan, branch, language, and security summary.
- Provide `POST /api/repositories/sync` to trigger manual synchronization.

Dependencies:
- fastapi.APIRouter, Depends, HTTPException, Query, Path, status
- sqlalchemy.orm.Session
- app.db.session.get_db
- app.db.repository.DatabaseRepository
- app.services.repo_sync_service.RepositorySyncService
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models import FindingModel, RepositoryModel, ScanModel
from app.db.repository import DatabaseRepository
from app.db.session import get_db
from app.services.repo_sync_service import RepositorySyncService

router = APIRouter(prefix="/api/repositories", tags=["Enterprise Repository Discovery"])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="Get Paginated Installed Repositories",
    description="Lists all GitHub App installed repositories with pagination and filtering.",
)
def get_repositories(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(default=None, description="Search query for repository name or owner"),
    language: Optional[str] = Query(default=None, description="Filter by primary programming language"),
    visibility: Optional[str] = Query(default=None, description="Filter by visibility (public, private, internal)"),
    archived: Optional[bool] = Query(default=None, description="Filter by archived status"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve paginated installed repositories with filtering."""
    dao = DatabaseRepository(db)
    return dao.get_paginated_repositories(
        page=page,
        page_size=page_size,
        search=search,
        language=language,
        visibility=visibility,
        archived=archived,
    )


@router.get(
    "/{owner}/{repo}",
    status_code=status.HTTP_200_OK,
    summary="Get Repository Security Profile",
    description="Returns detailed repository metadata, latest scan details, branch, language, and finding counts.",
)
def get_repository_details(
    owner: str = Path(..., description="Repository owner (e.g. NATTOMR)"),
    repo: str = Path(..., description="Repository name (e.g. secureguard-github-app)"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve detailed security information for a specific repository."""
    dao = DatabaseRepository(db)
    repo_model = dao.get_repository_by_owner_repo(owner, repo)

    if not repo_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository {owner}/{repo} not found",
        )

    # Fetch latest scan
    latest_scan = (
        db.execute(
            select(ScanModel)
            .where(ScanModel.repository_id == repo_model.id)
            .order_by(desc(ScanModel.started_at))
            .limit(1)
        )
        .scalar_one_or_none()
    )

    # Fetch finding counts by severity
    findings_stmt = (
        select(FindingModel.severity, FindingModel.scanner, FindingModel.rule)
        .join(ScanModel, ScanModel.id == FindingModel.scan_id)
        .where(ScanModel.repository_id == repo_model.id)
    )
    findings = db.execute(findings_stmt).all()

    critical_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity.upper() == "HIGH")
    medium_count = sum(1 for f in findings if f.severity.upper() == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity.upper() == "LOW")
    risk_score = critical_count * 10 + high_count * 5 + medium_count * 2 + low_count * 1

    # Security risk grade
    if risk_score == 0:
        grade = "A+"
    elif risk_score <= 10:
        grade = "A"
    elif risk_score <= 30:
        grade = "B"
    elif risk_score <= 60:
        grade = "C"
    else:
        grade = "F"

    latest_scan_details = None
    if latest_scan:
        latest_scan_details = {
            "scan_id": latest_scan.id,
            "commit_sha": latest_scan.commit_sha,
            "branch": latest_scan.branch,
            "trigger": latest_scan.trigger,
            "status": latest_scan.status,
            "started_at": latest_scan.started_at.isoformat() if latest_scan.started_at else None,
            "finished_at": latest_scan.finished_at.isoformat() if latest_scan.finished_at else None,
            "duration": latest_scan.duration,
            "total_findings": len(latest_scan.findings),
        }

    return {
        "repository": {
            "id": repo_model.id,
            "github_repository_id": repo_model.github_repository_id,
            "owner": repo_model.owner,
            "name": repo_model.name,
            "full_name": repo_model.full_name or f"{repo_model.owner}/{repo_model.name}",
            "private": repo_model.private,
            "visibility": repo_model.visibility or "public",
            "default_branch": repo_model.default_branch or "main",
            "language": repo_model.language or "Unknown",
            "size": repo_model.size,
            "archived": repo_model.archived,
            "disabled": repo_model.disabled,
            "is_active": repo_model.is_active,
            "html_url": repo_model.html_url or f"https://github.com/{repo_model.owner}/{repo_model.name}",
            "clone_url": repo_model.clone_url or f"https://github.com/{repo_model.owner}/{repo_model.name}.git",
            "last_push": repo_model.last_push.isoformat() if repo_model.last_push else None,
            "last_sync": repo_model.last_sync.isoformat() if repo_model.last_sync else None,
            "created_at": repo_model.created_at.isoformat() if repo_model.created_at else None,
        },
        "latest_scan": latest_scan_details,
        "finding_counts": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "total": len(findings),
        },
        "security_summary": {
            "risk_score": risk_score,
            "grade": grade,
            "status": "COMPLIANT" if critical_count == 0 and high_count == 0 else "NON_COMPLIANT",
        },
    }


@router.post(
    "/sync",
    status_code=status.HTTP_200_OK,
    summary="Trigger Manual Repository Discovery Sync",
    description="Synchronizes installed GitHub App repositories into the database.",
)
async def sync_repositories(
    installation_id: Optional[int] = Query(default=None, description="Optional GitHub App installation ID"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Manually trigger repository discovery sync."""
    sync_service = RepositorySyncService()
    results = await sync_service.sync_installation(installation_id=installation_id, db=db)
    
    return {
        "status": "success",
        "added": results["repositories_added"],
        "updated": results["repositories_updated"],
        "removed": results["repositories_removed"],
    }
