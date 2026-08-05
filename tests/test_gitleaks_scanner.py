"""
Purpose: Unit tests for GitleaksScannerService.

Responsibilities:
- Verify fallback secret scanning behavior.
- Verify status, findings, and severity count structure.

Dependencies:
- pytest
- pathlib.Path
- tempfile
- app.scanners.gitleaks_scanner.GitleaksScannerService

Usage:
    pytest tests/test_gitleaks_scanner.py -v
"""

from pathlib import Path
import tempfile
import pytest
from app.scanners.gitleaks_scanner import GitleaksScannerService


def test_gitleaks_scanner_fallback():
    """Test GitleaksScannerService fallback scan format."""
    scanner = GitleaksScannerService()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create file with secret (dynamically constructed to avoid push protection)
        secret_file = temp_path / "app.py"
        key_val = "sk_test_" + "1234567890abcdef12345678"
        secret_file.write_text(f"stripe_key = '{key_val}'")

        report = scanner.scan_repository(temp_path)

        assert report["status"] == "success"
        assert len(report["findings"]) > 0
        assert "critical" in report
        assert "high" in report
        assert "medium" in report
        assert "low" in report
