"""
Purpose: Service for orchestrating Pull Request code checkout and multi-scanner execution.

Responsibilities:
- Clone target repository and checkout PR branch/commit.
- Execute secret scanner (Gitleaks) and SAST scanner (Semgrep).
- Aggregate and format findings into domain ScanResult object.
- Safely clean up temporary clone directory.

Dependencies:
- subprocess
- uuid
- datetime
- pathlib.Path
- typing.List, Optional, Dict, Any
- app.models.scan_result.ScanResult, Finding
- app.services.github_clone.GitHubCloneService
- app.scanners.gitleaks_scanner.GitleaksScannerService
- app.scanners.semgrep.SemgrepScanner
- app.auth.github_auth.GitHubAuthManager
- app.core.logging.get_logger

Usage:
    pr_scanner = PRScanService(auth_manager=auth_manager)
    scan_result = await pr_scanner.scan_pull_request(
        owner="octocat",
        repo="Hello-World",
        pr_number=42,
        head_ref="feature-branch",
        head_sha="7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
        installation_id=123456
    )
"""

import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from app.auth.github_auth import GitHubAuthManager
from app.core.logging import get_logger
from app.models.scan_result import Finding, ScanResult
from app.scanners.gitleaks_scanner import GitleaksScannerService
from app.scanners.semgrep import SemgrepScanner
from app.services.github_clone import GitHubCloneService

logger = get_logger(__name__)


class PRScanService:
    """Service handling Pull Request branch checkout and dual security scanning."""

    def __init__(
        self,
        clone_service: Optional[GitHubCloneService] = None,
        gitleaks_scanner: Optional[GitleaksScannerService] = None,
        semgrep_scanner: Optional[SemgrepScanner] = None,
        auth_manager: Optional[GitHubAuthManager] = None,
    ) -> None:
        self.clone_service = clone_service or GitHubCloneService()
        self.gitleaks_scanner = gitleaks_scanner or GitleaksScannerService()
        self.semgrep_scanner = semgrep_scanner or SemgrepScanner()
        self.auth_manager = auth_manager

    async def scan_pull_request(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        head_ref: str,
        head_sha: str,
        installation_id: Optional[int] = None,
    ) -> ScanResult:
        """Clone PR repository, checkout branch, run scanners, and aggregate results."""
        scan_id = str(uuid.uuid4())
        logger.info(
            "Starting PR scan %s for %s/%s PR #%d (branch: %s, sha: %s)",
            scan_id, owner, repo, pr_number, head_ref, head_sha
        )

        token = None
        if self.auth_manager and installation_id:
            try:
                token = await self.auth_manager.get_installation_token(installation_id)
            except Exception as e:
                logger.warning("Failed to obtain installation token for PR clone: %s", str(e))

        clone_url = f"https://github.com/{owner}/{repo}.git"
        temp_dir: Optional[Path] = None
        all_findings: List[Finding] = []

        try:
            # 1. Clone repository
            temp_dir = self.clone_service.clone_repository(clone_url, token=token, commit_sha=head_sha)
            
            # 2. Checkout PR branch if ref provided
            if head_ref and temp_dir:
                self._checkout_branch(temp_dir, head_ref)

            # 3. Run Gitleaks scanner
            if temp_dir:
                logger.info("Executing Gitleaks scan on PR workspace %s", temp_dir)
                gitleaks_report = self.gitleaks_scanner.scan_repository(temp_dir)
                for f in gitleaks_report.get("findings", []):
                    all_findings.append(
                        Finding(
                            rule_id=f.get("rule", "gitleaks-leak"),
                            title=f.get("title", "Secret Leak"),
                            severity=f.get("severity", "HIGH"),
                            file_path=f.get("file", "unknown"),
                            line_number=f.get("line"),
                            description=f.get("description", "Exposed credential detected"),
                            recommendation="Move secret or token to secure environment variables or secret manager.",
                            scanner_name="Gitleaks",
                        )
                    )

            # 4. Run Semgrep SAST scanner
            if temp_dir:
                logger.info("Executing Semgrep SAST scan on PR workspace %s", temp_dir)
                try:
                    sast_findings = await self.semgrep_scanner.scan(temp_dir)
                    for sf in sast_findings:
                        all_findings.append(
                            Finding(
                                rule_id=sf.get("rule_id", "sast-vuln"),
                                title=sf.get("title", "SAST Vulnerability"),
                                severity=sf.get("severity", "MEDIUM"),
                                file_path=sf.get("file_path", "unknown"),
                                line_number=sf.get("line_number"),
                                description=sf.get("description"),
                                recommendation=sf.get("recommendation", "Refactor code according to secure coding best practices."),
                                scanner_name=sf.get("scanner_name", "Semgrep"),
                            )
                        )
                except Exception as se:
                    logger.error("Semgrep SAST scan failed during PR scan: %s", str(se))

        finally:
            # 5. Cleanup temp directory
            if temp_dir:
                self.clone_service.cleanup_repository(temp_dir)
                logger.info("Cleaned up PR temp workspace %s", temp_dir)

        # 6. Build final ScanResult domain model
        result = ScanResult(
            scan_id=scan_id,
            repository=f"{owner}/{repo}",
            commit_sha=head_sha,
            timestamp=datetime.now(timezone.utc),
            findings=all_findings,
        )

        logger.info(
            "Completed PR scan %s for %s/%s PR #%d. Total findings: %d.",
            scan_id, owner, repo, pr_number, result.total_findings
        )
        return result

    def _checkout_branch(self, target_dir: Path, head_ref: str) -> None:
        """Attempt git checkout of PR head branch."""
        try:
            res = subprocess.run(
                ["git", "checkout", head_ref],
                cwd=target_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if res.returncode == 0:
                logger.info("Successfully checked out branch %s in %s", head_ref, target_dir)
            else:
                logger.warning("Branch checkout non-zero exit code: %s", res.stderr)
        except Exception as e:
            logger.warning("Could not checkout branch %s: %s", head_ref, str(e))
