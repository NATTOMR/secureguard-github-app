"""
Purpose: Production Gitleaks CLI scanner module with native fallback.

Responsibilities:
- Execute Gitleaks CLI with JSON report output against target repository directory.
- Apply timeout protection and graceful error handling.
- Fall back to native secret rules engine if Gitleaks CLI binary is absent.
- Map raw findings into structured FindingModel list and severity counts.

Dependencies:
- subprocess
- json
- shutil
- pathlib.Path
- app.models.finding.FindingModel
- app.scanners.secret_rules.detect_secrets
- app.core.logging.get_logger

Usage:
    scanner = GitleaksScannerService(binary_path="gitleaks", timeout=120)
    report = scanner.scan_repository(Path("/path/to/repo"))
"""

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.logging import get_logger
from app.models.finding import FindingModel
from app.scanners.secret_rules import detect_secrets

logger = get_logger(__name__)


class GitleaksScannerService:
    """Service executing Gitleaks security scans with JSON parsing and fallback."""

    def __init__(self, binary_path: str = "gitleaks", timeout: int = 120) -> None:
        self.binary_path = binary_path
        self.timeout = timeout

    def _is_gitleaks_available(self) -> bool:
        """Check if Gitleaks binary is available on PATH."""
        return shutil.which(self.binary_path) is not None

    def scan_repository(self, target_dir: Path) -> Dict[str, Any]:
        """Execute Gitleaks scan on target repository directory."""
        logger.info("Starting Gitleaks scan on directory: %s", target_dir)

        if self._is_gitleaks_available():
            logger.info("Using Gitleaks CLI binary (%s)", self.binary_path)
            return self._run_gitleaks_cli(target_dir)

        logger.info("Gitleaks CLI not found on PATH. Falling back to native secret engine.")
        return self._run_native_fallback(target_dir)

    def _run_gitleaks_cli(self, target_dir: Path) -> Dict[str, Any]:
        """Execute Gitleaks CLI binary and parse JSON output."""
        report_file = target_dir / "gitleaks_report.json"
        cmd = [
            self.binary_path,
            "detect",
            "--source", str(target_dir),
            "--report-path", str(report_file),
            "--report-format", "json",
            "--no-git",
            "--redact",
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            # Gitleaks exits with code 1 if leaks are found, 0 if clean
            if res.returncode not in (0, 1):
                logger.warning("Gitleaks CLI exited with unexpected code %d: %s", res.returncode, res.stderr)
        except subprocess.TimeoutExpired:
            logger.error("Gitleaks CLI timed out after %d seconds. Falling back to native scanner.", self.timeout)
            return self._run_native_fallback(target_dir)
        except Exception as e:
            logger.error("Gitleaks CLI execution error: %s. Falling back to native scanner.", str(e))
            return self._run_native_fallback(target_dir)

        findings: List[FindingModel] = []
        if report_file.exists() and report_file.stat().st_size > 0:
            try:
                raw_json = json.loads(report_file.read_text(encoding="utf-8"))
                for item in raw_json:
                    finding = FindingModel(
                        id=str(uuid.uuid4()),
                        title=item.get("Description", "Detected Secret"),
                        description=item.get("Match", "Secret matched rule"),
                        severity="CRITICAL",
                        file=item.get("File", "unknown"),
                        line=item.get("StartLine"),
                        rule=item.get("RuleID", "gitleaks-rule"),
                        secret_type=item.get("RuleID", "Secret"),
                        commit=item.get("Commit"),
                        author=item.get("Author"),
                    )
                    findings.append(finding)
            except Exception as e:
                logger.error("Failed to parse Gitleaks JSON output: %s", str(e))

        return self._build_report_response("success", findings)

    def _run_native_fallback(self, target_dir: Path) -> Dict[str, Any]:
        """Run native Python secret scanning fallback."""
        findings: List[FindingModel] = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for file_name in files:
                file_path = Path(root) / file_name
                try:
                    content = file_path.read_text(encoding="utf-8")
                    rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")
                    raw_findings = detect_secrets(content, rel_path)
                    for raw in raw_findings:
                        finding = FindingModel(
                            id=str(uuid.uuid4()),
                            title=raw.get("title", "Secret Leak"),
                            description=raw.get("description", "Exposed credential"),
                            severity=raw.get("severity", "HIGH"),
                            file=raw.get("file_path", rel_path),
                            line=raw.get("line_number"),
                            rule=raw.get("rule_id", "secret-leak"),
                            secret_type=raw.get("rule_id", "Credential"),
                            commit=None,
                            author=None,
                        )
                        findings.append(finding)
                except Exception:
                    continue

        return self._build_report_response("success", findings)

    def _build_report_response(self, status: str, findings: List[FindingModel]) -> Dict[str, Any]:
        """Calculate severity summary and return required dictionary format."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity.upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["LOW"] += 1

        return {
            "status": status,
            "findings": [f.model_dump() for f in findings],
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
        }
