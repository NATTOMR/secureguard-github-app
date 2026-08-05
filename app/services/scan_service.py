"""
Purpose: Scan orchestrator service (Phase 3).

Responsibilities:
- Coordinate downloading of target repository.
- Execute registered security scanner plugins.
- Consolidate and format scan findings.
- Safely clean up temporary files.

Dependencies:
- app.scanners.base.BaseScanner
- app.services.repository_service.RepositoryService
- app.models.scan_result.ScanResult, Finding
- app.core.logging.get_logger
- uuid
- datetime

Usage:
    service = ScanService(scanners=[GitleaksScanner()], repo_service=repo_service)
    report = await service.execute_scan("owner", "repo", "commit_sha", 123456)
"""

import asyncio
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from app.models.scan_result import Finding, ScanResult
from app.scanners.base import BaseScanner
from app.services.repository_service import RepositoryService
from app.core.logging import get_logger

logger = get_logger(__name__)


from app.auth.github_auth import GitHubAuthManager
from app.scanners.gitleaks_scanner import GitleaksScannerService
from app.services.github_clone import GitHubCloneService


class ScanService:
    """Orchestrates security scanning operations on target repositories."""

    def __init__(
        self,
        scanners: Optional[List[BaseScanner]] = None,
        repo_service: Optional[RepositoryService] = None,
        clone_service: Optional[GitHubCloneService] = None,
        gitleaks_scanner: Optional[GitleaksScannerService] = None,
        auth_manager: Optional[GitHubAuthManager] = None,
    ) -> None:
        self.scanners = scanners or []
        self.repo_service = repo_service
        self.clone_service = clone_service or GitHubCloneService()
        self.gitleaks_scanner = gitleaks_scanner or GitleaksScannerService()
        self.auth_manager = auth_manager

    async def run_gitleaks_pipeline(
        self, owner: str, repo: str, commit_sha: Optional[str] = None, installation_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Run complete Gitleaks scanning pipeline: clone -> scan -> summarize -> cleanup."""
        logger.info("Executing Gitleaks pipeline for %s/%s", owner, repo)

        token = None
        if self.auth_manager and installation_id:
            try:
                token = await self.auth_manager.get_installation_token(installation_id)
            except Exception as e:
                logger.warning("Failed to obtain installation token for clone: %s", str(e))

        clone_url = f"https://github.com/{owner}/{repo}.git"
        temp_path = None
        try:
            # 1. Clone repository
            temp_path = self.clone_service.clone_repository(clone_url, token, commit_sha)
            
            # 2. Run Gitleaks scanner
            report = self.gitleaks_scanner.scan_repository(temp_path)
            
            logger.info(
                "Pipeline finished for %s/%s: %d critical, %d high, %d medium, %d low findings.",
                owner, repo, report["critical"], report["high"], report["medium"], report["low"]
            )
            return report
        finally:
            # 3. Cleanup temp directory
            if temp_path:
                self.clone_service.cleanup_repository(temp_path)

    async def execute_scan(
        self, owner: str, repo: str, commit_sha: str, installation_id: Optional[int] = None
    ) -> ScanResult:
        """Execute full scan pipeline on target commit."""
        scan_id = str(uuid.uuid4())
        logger.info("Starting scan %s for %s/%s at commit %s", scan_id, owner, repo, commit_sha)
        
        # 1. Download repository
        temp_dir = None
        all_findings: List[Finding] = []
        
        try:
            if self.repo_service:
                temp_dir = await self.repo_service.download_repository(
                    owner, repo, commit_sha, installation_id
                )
            
            # 2. Run scanners
            for scanner in self.scanners:
                if not temp_dir:
                    continue
                logger.info("Running scanner %s on %s", scanner.name, temp_dir)
                try:
                    raw_findings = await scanner.scan(temp_dir)
                    # Convert raw dicts to Finding objects
                    for raw in raw_findings:
                        finding = Finding(
                            rule_id=raw.get("rule_id", "unknown"),
                            title=raw.get("title", "Unknown Secret"),
                            severity=raw.get("severity", "INFO"),
                            file_path=raw.get("file_path", "unknown"),
                            line_number=raw.get("line_number"),
                            description=raw.get("description"),
                            recommendation=raw.get("recommendation"),
                            scanner_name=raw.get("scanner_name", scanner.name),
                        )
                        all_findings.append(finding)
                except Exception as e:
                    logger.error("Scanner %s failed: %s", scanner.name, str(e))
                    
        finally:
            # 3. Cleanup
            if temp_dir and self.repo_service:
                self.repo_service.cleanup_repository(temp_dir)
                
        # 4. Aggregate results
        result = ScanResult(
            scan_id=scan_id,
            repository=f"{owner}/{repo}",
            commit_sha=commit_sha,
            timestamp=datetime.now(timezone.utc),
            findings=all_findings
        )
        
        logger.info(
            "Completed scan %s for %s/%s. Found %d issues.", 
            scan_id, owner, repo, result.total_findings
        )

        # 5. Dispatch ScanCompleted event to enterprise SOC integrations
        try:
            from app.integrations.connector_manager import ConnectorManager
            manager = ConnectorManager()
            scan_dict = {
                "scan_id": scan_id,
                "repository": f"{owner}/{repo}",
                "commit_sha": commit_sha,
                "total_findings": result.total_findings,
                "critical_findings": result.critical_findings,
                "high_findings": result.high_findings,
                "timestamp": result.timestamp.isoformat(),
            }
            asyncio.create_task(manager.dispatch_scan_completed(scan_dict))
        except Exception as e:
            logger.warning("EventBus dispatch error: %s", str(e))

        return result
