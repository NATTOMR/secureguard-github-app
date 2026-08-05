"""
Purpose: API routes for triggering security scans.

Responsibilities:
- Provide `POST /scan` to initiate a security scan on a repository commit.

Dependencies:
- fastapi.APIRouter, Depends, HTTPException, status
- app.core.config.get_settings, Settings
- app.auth.github_auth.GitHubAuthManager
- app.services.repository_service.RepositoryService
- app.scanners.gitleaks.GitleaksScanner
- app.services.scan_service.ScanService
- app.schemas.scan.ScanRequest, ScanResponse

Usage:
    Included in FastAPI router.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from app.auth.github_auth import GitHubAuthManager
from app.core.config import Settings, get_settings
from app.core.exceptions import SecureGuardError
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.semgrep import SemgrepScanner
from app.services.notification_service import GitHubNotificationService
from app.services.repository_service import RepositoryService
from app.services.scan_service import ScanService
from app.schemas.scan import ScanRequest, ScanResponse

router = APIRouter(prefix="/scan", tags=["Security Scanning"])


def get_scan_service(settings: Settings = Depends(get_settings)) -> ScanService:
    """Dependency provider for ScanService with all registered scanners."""
    auth_manager = GitHubAuthManager(settings)
    repo_service = RepositoryService(auth_manager)
    scanners = [GitleaksScanner(), SemgrepScanner()]
    return ScanService(scanners=scanners, repo_service=repo_service)


def get_notification_service(settings: Settings = Depends(get_settings)) -> GitHubNotificationService:
    """Dependency provider for GitHubNotificationService."""
    auth_manager = GitHubAuthManager(settings)
    return GitHubNotificationService(auth_manager=auth_manager)


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger a Security Scan",
    description="Initiates a security scan (Secrets + SAST) on a specified repository and commit SHA, and posts findings to GitHub.",
)
async def trigger_scan(
    request: ScanRequest,
    scan_service: ScanService = Depends(get_scan_service),
    notification_service: GitHubNotificationService = Depends(get_notification_service),
) -> ScanResponse:
    """Trigger a new security scan."""
    try:
        result = await scan_service.execute_scan(
            owner=request.owner,
            repo=request.repo,
            commit_sha=request.commit_sha,
            installation_id=request.installation_id,
        )
        
        notification_summary = {"github_comment_posted": False, "github_issues_created": 0}
        if request.notify_github:
            notification_summary = await notification_service.notify(
                scan_result=result,
                owner=request.owner,
                repo=request.repo,
                pr_number=request.pr_number,
                installation_id=request.installation_id,
            )
        
        # Map domain model Finding to Pydantic FindingSchema
        findings = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "description": f.description,
                "recommendation": f.recommendation,
                "scanner_name": f.scanner_name,
            }
            for f in result.findings
        ]
        
        return ScanResponse(
            scan_id=result.scan_id,
            repository=result.repository,
            commit_sha=result.commit_sha,
            timestamp=result.timestamp,
            total_findings=result.total_findings,
            has_critical_or_high=result.has_critical_or_high,
            github_comment_posted=notification_summary["github_comment_posted"],
            github_issues_created=notification_summary["github_issues_created"],
            findings=findings,
        )
    except SecureGuardError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan failed due to application error: {e.message}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error during scan: {str(e)}",
        )
