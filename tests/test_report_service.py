"""
Purpose: Automated tests for ReportService markdown generation.

Responsibilities:
- Verify that markdown report includes summary metrics, scan ID, commit SHA.
- Verify that findings are grouped by severity correctly.

Dependencies:
- pytest
- app.models.scan_result.ScanResult, Finding
- app.services.report_service.ReportService
- datetime

Usage:
    pytest tests/test_report_service.py -v
"""

from datetime import datetime, timezone
from app.models.scan_result import ScanResult, Finding
from app.services.report_service import ReportService


def test_report_generation_with_findings():
    """Test generating a markdown report with critical and high findings."""
    result = ScanResult(
        scan_id="test-scan-123",
        repository="owner/repo",
        commit_sha="abc1234",
        timestamp=datetime.now(timezone.utc),
        findings=[
            Finding(
                rule_id="github-pat",
                title="GitHub Token Leaked",
                severity="CRITICAL",
                file_path="config.py",
                line_number=10,
                description="Leaked token found",
                recommendation="Revoke token",
                scanner_name="Gitleaks",
            ),
            Finding(
                rule_id="python-eval",
                title="Code Injection via eval()",
                severity="HIGH",
                file_path="main.py",
                line_number=42,
                description="eval() called on input",
                recommendation="Avoid eval()",
                scanner_name="Semgrep",
            ),
        ],
    )

    service = ReportService()
    report = service.generate(result)

    assert "# SecureGuard Scan Report – test-scan-123" in report
    assert "**Repository:** owner/repo" in report
    assert "**Commit:** abc1234" in report
    assert "| Total Findings | 2 |" in report
    assert "| Critical | 1 |" in report
    assert "| High | 1 |" in report
    assert "## Critical Findings (1)" in report
    assert "## High Findings (1)" in report
    assert "`config.py`:10 – GitHub Token Leaked" in report
    assert "`main.py`:42 – Code Injection via eval()" in report


def test_report_generation_clean_scan():
    """Test generating a markdown report when no findings are detected."""
    result = ScanResult(
        scan_id="clean-scan-456",
        repository="owner/clean-repo",
        commit_sha="def5678",
        timestamp=datetime.now(timezone.utc),
        findings=[],
    )

    service = ReportService()
    report = service.generate(result)

    assert "# SecureGuard Scan Report – clean-scan-456" in report
    assert "| Total Findings | 0 |" in report
    assert "| Critical | 0 |" in report
    assert "| High | 0 |" in report
    assert "## Critical Findings" not in report
