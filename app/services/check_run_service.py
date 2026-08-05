"""
Purpose: Service for converting scan findings into GitHub Check Runs and Annotations.

Responsibilities:
- Transform ScanResult domain models into GitHub Annotations.
- Format Markdown summary tables and detailed text output with severity icons.
- Compute check conclusion (failure, neutral, success) based on severity rules.
- Orchestrate Check Run creation, status updates (queued -> in_progress -> completed), and publication.

Dependencies:
- typing.Dict, List, Any, Optional
- app.models.scan_result.ScanResult, Finding
- app.github.checks_service.GitHubChecksService
- app.core.config.get_settings
- app.core.logging.get_logger

Usage:
    check_run_service = CheckRunService()
    result = await check_run_service.publish_scan_checks(
        owner="octocat", repo="Hello-World", head_sha="7fd1a60b", scan_result=scan_result, token="ghs_...", check_run_id=123
    )
"""

from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.core.logging import get_logger
from app.github.checks_service import GitHubChecksService
from app.models.scan_result import Finding, ScanResult

logger = get_logger(__name__)


class CheckRunService:
    """Orchestrates conversion of ScanResult to GitHub Checks & Annotations."""

    def __init__(self, checks_service: Optional[GitHubChecksService] = None) -> None:
        self.checks_service = checks_service or GitHubChecksService()
        self.settings = get_settings()

    def determine_conclusion(self, scan_result: ScanResult) -> str:
        """Determine Check Run conclusion based on severity rules.
        
        Rules:
        - Critical > 0 OR High > 0 => "failure"
        - Medium > 0 => "neutral"
        - Zero findings => "success"
        """
        if scan_result.critical_findings > 0 or scan_result.high_findings > 0:
            return "failure"
        
        medium_findings = sum(1 for f in scan_result.findings if f.severity.upper() == "MEDIUM")
        if medium_findings > 0:
            return "neutral"
            
        return "success"

    def build_annotations(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Convert findings list into GitHub Check Run Annotation objects (capped at MAX_ANNOTATIONS)."""
        annotations: List[Dict[str, Any]] = []
        max_limit = self.settings.MAX_ANNOTATIONS

        for finding in findings[:max_limit]:
            sev_upper = finding.severity.upper()
            
            # Map severity to GitHub annotation_level (failure, warning, notice)
            if sev_upper in ("CRITICAL", "HIGH"):
                level = "failure"
            elif sev_upper == "MEDIUM":
                level = "warning"
            else:
                level = "notice"

            line = finding.line_number if finding.line_number and finding.line_number > 0 else 1

            annotation = {
                "path": finding.file_path,
                "start_line": line,
                "end_line": line,
                "annotation_level": level,
                "title": finding.title,
                "message": finding.recommendation or finding.description or "Security issue detected by SecureGuard.",
            }
            annotations.append(annotation)

        logger.info("Generated %d GitHub annotations (max limit: %d)", len(annotations), max_limit)
        return annotations

    def build_check_output(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Build GitHub Check Run output dictionary (title, summary, text, annotations)."""
        title = self.settings.CHECK_RUN_NAME
        critical_cnt = scan_result.critical_findings
        high_cnt = scan_result.high_findings
        medium_cnt = sum(1 for f in scan_result.findings if f.severity.upper() == "MEDIUM")
        low_cnt = sum(1 for f in scan_result.findings if f.severity.upper() in ("LOW", "INFO"))

        summary_lines = [
            "### Repository scanned successfully.\n",
            "| Severity | Count |",
            "|----------|------:|",
            f"| Critical | {critical_cnt} |",
            f"| High | {high_cnt} |",
            f"| Medium | {medium_cnt} |",
            f"| Low | {low_cnt} |\n",
        ]
        summary = "\n".join(summary_lines)

        text_lines: List[str] = []
        if scan_result.total_findings == 0:
            text_lines.append("# ✅ Passed\n\nNo security vulnerabilities or secret leaks were detected in this commit.")
        else:
            # Categorize findings by severity
            categories = {
                "CRITICAL": ("🔴 Critical Findings", []),
                "HIGH": ("🟠 High Findings", []),
                "MEDIUM": ("🟡 Medium Findings", []),
                "LOW": ("🔵 Low Findings", []),
            }

            for f in scan_result.findings:
                sev = f.severity.upper()
                if sev in categories:
                    categories[sev][1].append(f)
                else:
                    categories["LOW"][1].append(f)

            for key, (header, finding_list) in categories.items():
                if finding_list:
                    text_lines.append(f"## {header}\n")
                    for f in finding_list:
                        text_lines.append(f"**{f.title}**")
                        text_lines.append(f"- **File:** `{f.file_path}` (Line {f.line_number or 'N/A'})")
                        text_lines.append(f"- **Rule:** `{f.rule_id}`")
                        text_lines.append(f"- **Description:** {f.description or 'N/A'}")
                        if f.recommendation:
                            text_lines.append(f"- **Recommendation:** {f.recommendation}")
                        text_lines.append("")

        text = "\n".join(text_lines)
        annotations = self.build_annotations(scan_result.findings)

        return {
            "title": title,
            "summary": summary,
            "text": text,
            "annotations": annotations,
        }

    async def publish_scan_checks(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        scan_result: ScanResult,
        token: str,
        check_run_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Publish scan results and annotations to GitHub Checks API."""
        if not self.settings.GITHUB_CHECKS_ENABLED:
            logger.info("GitHub Checks API reporting is disabled in settings.")
            return {"status": "disabled"}

        # 1. If check_run_id is not passed, create a new check run
        if not check_run_id:
            check_run_id = await self.checks_service.create_check_run(
                owner=owner,
                repo=repo,
                head_sha=head_sha,
                name=self.settings.CHECK_RUN_NAME,
                token=token,
                status="in_progress",
            )

        # 2. Build output & conclusion
        output = self.build_check_output(scan_result)
        conclusion = self.determine_conclusion(scan_result)

        # 3. Update check run to completed
        logger.info("Publishing completed Check Run #%d with conclusion '%s'", check_run_id, conclusion)
        result = await self.checks_service.update_check_run(
            owner=owner,
            repo=repo,
            check_run_id=check_run_id,
            token=token,
            status="completed",
            conclusion=conclusion,
            output=output,
        )
        return result
