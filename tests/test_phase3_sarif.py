"""
Purpose: Automated tests for SARIF 2.1.0 report generation service.
"""

from datetime import datetime, timezone
import pytest

from app.db.models import FindingModel, RepositoryModel, ScanModel
from app.services.sarif_service import SARIFService


def test_sarif_generation():
    """Test SARIF 2.1.0 report schema generation."""
    repo = RepositoryModel(id=1, owner="NATTOMR", name="test-repo")
    scan = ScanModel(
        id="scan-uuid-123",
        repository_id=1,
        commit_sha="7fd1a60",
        branch="main",
        trigger="push",
        status="completed",
        started_at=datetime.now(timezone.utc),
        repository=repo,
    )
    finding = FindingModel(
        id="find-uuid-456",
        scan_id="scan-uuid-123",
        scanner="Gitleaks",
        severity="HIGH",
        title="AWS Key Exposed",
        description="Exposed AWS Access Key ID",
        file="config.py",
        line=42,
        rule="gitleaks-aws-key",
        cwe="CWE-798",
        owasp="A07:2021",
    )
    scan.findings = [finding]

    service = SARIFService()
    sarif = service.generate_sarif(scan)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SecureGuard"
    assert len(driver["rules"]) == 1
    assert driver["rules"][0]["id"] == "gitleaks-aws-key"

    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "gitleaks-aws-key"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "config.py"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
