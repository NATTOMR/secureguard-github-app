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

import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from app.models.scan_result import Finding, ScanResult
from app.scanners.base import BaseScanner
from app.services.repository_service import RepositoryService
from app.core.logging import get_logger

logger = get_logger(__name__)


class ScanService:
    """Orchestrates security scanning operations on target repositories."""

    def __init__(self, scanners: List[BaseScanner], repo_service: RepositoryService) -> None:
        self.scanners = scanners
        self.repo_service = repo_service

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
            temp_dir = await self.repo_service.download_repository(
                owner, repo, commit_sha, installation_id
            )
            
            # 2. Run scanners
            for scanner in self.scanners:
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
            if temp_dir:
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
        return result
