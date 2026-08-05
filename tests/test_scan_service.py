"""
Purpose: Automated tests for ScanService orchestration.

Responsibilities:
- Verify that ScanService correctly coordinates downloading and scanning.
- Verify that ScanService handles cleanup appropriately.

Dependencies:
- pytest
- unittest.mock
- app.services.scan_service.ScanService
- app.services.repository_service.RepositoryService
- app.scanners.base.BaseScanner

Usage:
    pytest tests/test_scan_service.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
from app.services.scan_service import ScanService
from app.models.scan_result import ScanResult


class MockScanner:
    def __init__(self):
        self.name = "MockScanner"

    async def scan(self, target_dir):
        return [{"rule_id": "test-rule", "title": "Test Finding", "severity": "INFO", "file_path": "test.txt", "line_number": 1, "description": "test", "recommendation": "test", "scanner_name": self.name}]


@pytest.mark.asyncio
async def test_scan_service_execution():
    """Test full execution flow of ScanService."""
    mock_repo_service = MagicMock()
    # RepositoryService.download_repository is async
    mock_repo_service.download_repository = AsyncMock(return_value=Path("/tmp/mock_repo"))
    mock_repo_service.cleanup_repository = MagicMock()
    
    scanners = [MockScanner()]
    scan_service = ScanService(scanners=scanners, repo_service=mock_repo_service)
    
    result = await scan_service.execute_scan(owner="test_owner", repo="test_repo", commit_sha="abcdef")
    
    assert isinstance(result, ScanResult)
    assert result.total_findings == 1
    assert result.findings[0].rule_id == "test-rule"
    
    # Verify repo service was called correctly
    mock_repo_service.download_repository.assert_called_once_with("test_owner", "test_repo", "abcdef", None)
    mock_repo_service.cleanup_repository.assert_called_once_with(Path("/tmp/mock_repo"))
