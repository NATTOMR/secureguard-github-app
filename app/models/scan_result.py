"""
Purpose: Security scan domain models.

Responsibilities:
- Represent individual security findings, severity levels, and aggregated scan results.

Dependencies:
- dataclasses.dataclass, field
- datetime.datetime
- typing.List, Optional

Usage:
    finding = Finding(
        rule_id="GITLEAKS-001",
        title="AWS Access Key Exposed",
        severity="HIGH",
        file_path="config.py",
        line_number=42
    )
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class Finding:
    """Represents a single security vulnerability or secret finding."""

    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path: str
    line_number: Optional[int] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    scanner_name: Optional[str] = None


@dataclass
class ScanResult:
    """Represents the complete result of a security scan run."""

    scan_id: str
    repository: str
    commit_sha: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: List[Finding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "CRITICAL")

    @property
    def high_findings(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "HIGH")

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity.upper() in ("CRITICAL", "HIGH") for f in self.findings)
