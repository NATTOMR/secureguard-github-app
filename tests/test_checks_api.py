"""
Purpose: Test suite for GitHub Checks API Service and CheckRunService.

Responsibilities:
- Verify GitHub Check Run creation (queued / in_progress).
- Verify Check Run completion updates (completed / conclusion / output / annotations).
- Test conclusion determination logic (failure, neutral, success).
- Test annotation formatting and severity levels (failure, warning, notice).
- Test API retry behavior on transient errors.

Dependencies:
- pytest
- unittest.mock
- httpx
- app.github.checks_service.GitHubChecksService
- app.services.check_run_service.CheckRunService
- app.models.scan_result.ScanResult, Finding

Usage:
    pytest tests/test_checks_api.py -v
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.core.exceptions import GitHubAPIError
from app.github.checks_service import GitHubChecksService
from app.models.scan_result import Finding, ScanResult
from app.services.check_run_service import CheckRunService


@pytest.mark.asyncio
async def test_create_check_run_success():
    """Test successful creation of a queued or in_progress Check Run."""
    service = GitHubChecksService()
    mock_post = AsyncMock(return_value=MagicMock(status_code=201, json=lambda: {"id": 12345}))

    with patch("httpx.AsyncClient.post", mock_post):
        check_id = await service.create_check_run(
            owner="octocat",
            repo="Hello-World",
            head_sha="7fd1a60b",
            name="SecureGuard Security Scan",
            token="ghs_mock",
            status="in_progress",
        )

        assert check_id == 12345
        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["json"]["status"] == "in_progress"
        assert call_kwargs["json"]["name"] == "SecureGuard Security Scan"


@pytest.mark.asyncio
async def test_update_check_run_completed():
    """Test updating Check Run with completed status and conclusion."""
    service = GitHubChecksService()
    mock_patch = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: {"id": 12345, "status": "completed"}))

    with patch("httpx.AsyncClient.patch", mock_patch):
        res = await service.update_check_run(
            owner="octocat",
            repo="Hello-World",
            check_run_id=12345,
            token="ghs_mock",
            status="completed",
            conclusion="success",
            output={"title": "Test Output", "summary": "Clean scan"},
        )

        assert res["id"] == 12345
        assert mock_patch.called
        json_body = mock_patch.call_args[1]["json"]
        assert json_body["conclusion"] == "success"
        assert json_body["status"] == "completed"


def test_conclusion_determination_logic():
    """Test conclusion logic: failure for High/Critical, neutral for Medium, success for clean scan."""
    check_service = CheckRunService()

    # 1. Failure case (Critical/High)
    res_high = ScanResult(
        scan_id="s1",
        repository="r",
        commit_sha="c",
        timestamp=datetime.now(timezone.utc),
        findings=[Finding(rule_id="r1", title="Key Leak", severity="HIGH", file_path="a.py")],
    )
    assert check_service.determine_conclusion(res_high) == "failure"

    # 2. Neutral case (Medium)
    res_med = ScanResult(
        scan_id="s2",
        repository="r",
        commit_sha="c",
        timestamp=datetime.now(timezone.utc),
        findings=[Finding(rule_id="r2", title="Eval", severity="MEDIUM", file_path="b.py")],
    )
    assert check_service.determine_conclusion(res_med) == "neutral"

    # 3. Success case (Zero findings)
    res_clean = ScanResult(
        scan_id="s3",
        repository="r",
        commit_sha="c",
        timestamp=datetime.now(timezone.utc),
        findings=[],
    )
    assert check_service.determine_conclusion(res_clean) == "success"


def test_annotation_conversion():
    """Test converting domain Finding models into GitHub Annotations."""
    check_service = CheckRunService()
    findings = [
        Finding(
            rule_id="r1",
            title="Leaked AWS Key",
            severity="CRITICAL",
            file_path="config/aws.py",
            line_number=14,
            description="Exposed key",
            recommendation="Move to secrets",
        ),
        Finding(
            rule_id="r2",
            title="Insecure MD5",
            severity="MEDIUM",
            file_path="crypto.py",
            line_number=20,
            description="Use SHA-256",
        ),
    ]

    annotations = check_service.build_annotations(findings)

    assert len(annotations) == 2
    assert annotations[0]["path"] == "config/aws.py"
    assert annotations[0]["start_line"] == 14
    assert annotations[0]["annotation_level"] == "failure"
    assert annotations[0]["title"] == "Leaked AWS Key"
    assert annotations[1]["annotation_level"] == "warning"


@pytest.mark.asyncio
async def test_publish_scan_checks_end_to_end():
    """Test publish_scan_checks end to end flow."""
    mock_checks = MagicMock()
    mock_checks.create_check_run = AsyncMock(return_value=999)
    mock_checks.update_check_run = AsyncMock(return_value={"id": 999, "status": "completed"})

    check_service = CheckRunService(checks_service=mock_checks)
    scan_result = ScanResult(
        scan_id="s_test",
        repository="octocat/Hello-World",
        commit_sha="7fd1a60b",
        timestamp=datetime.now(timezone.utc),
        findings=[],
    )

    res = await check_service.publish_scan_checks(
        owner="octocat",
        repo="Hello-World",
        head_sha="7fd1a60b",
        scan_result=scan_result,
        token="ghs_mock",
    )

    assert res["status"] == "completed"
    assert mock_checks.create_check_run.called
    assert mock_checks.update_check_run.called


@pytest.mark.asyncio
async def test_checks_api_failure_retry():
    """Test retry behavior when GitHub Checks API returns transient errors."""
    service = GitHubChecksService()
    service.MAX_RETRIES = 2

    mock_post = AsyncMock(return_value=MagicMock(status_code=500, text="Internal Server Error"))

    with patch("httpx.AsyncClient.post", mock_post), patch("asyncio.sleep", AsyncMock()):
        with pytest.raises(GitHubAPIError):
            await service.create_check_run(
                owner="octocat",
                repo="Hello-World",
                head_sha="7fd1a60b",
                name="Scan",
                token="ghs_mock",
            )
    assert mock_post.call_count == 2
