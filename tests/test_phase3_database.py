"""
Purpose: Automated tests for Phase 3 database enhancements, GitHubIssueModel, and analytics DAO.
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import EventModel, FindingModel, GitHubIssueModel, RepositoryModel, ScanModel
from app.db.repository import DatabaseRepository
from app.models.scan_result import Finding, ScanResult


@pytest.fixture
def db_session():
    """Create in-memory SQLite database session for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_github_issue_model_crud(db_session):
    """Test creating, reading, and querying GitHubIssueModel."""
    dao = DatabaseRepository(db_session)
    repo = dao.get_or_create_repository("test-owner", "test-repo")
    scan = ScanModel(id="scan-123", repository_id=repo.id, commit_sha="abc1234")
    db_session.add(scan)
    db_session.flush()

    finding = FindingModel(
        id="find-123",
        scan_id="scan-123",
        scanner="Gitleaks",
        severity="HIGH",
        title="AWS Key Exposed",
        file="config.py",
        rule="gitleaks-aws-key",
    )
    db_session.add(finding)
    db_session.commit()

    # Create issue record
    issue = dao.create_github_issue_record("find-123", 42, "https://github.com/test-owner/test-repo/issues/42")
    assert issue.id is not None
    assert issue.issue_number == 42
    assert issue.status == "open"

    # Query
    issues = dao.get_github_issues()
    assert len(issues) == 1
    assert issues[0].issue_number == 42

    # Check existence helper
    assert dao.issue_exists_for_finding("find-123") is True
    assert dao.issue_exists_for_finding("non-existent") is False


def test_dao_trend_and_leaderboard(db_session):
    """Test get_trend_data and get_repository_leaderboard."""
    dao = DatabaseRepository(db_session)
    repo = dao.get_or_create_repository("acme", "sec-repo")
    scan = ScanModel(id="s1", repository_id=repo.id, commit_sha="111", started_at=datetime.now(timezone.utc))
    db_session.add(scan)
    db_session.flush()

    f1 = FindingModel(id="f1", scan_id="s1", scanner="Semgrep", severity="CRITICAL", title="SQLi", file="app.py", rule="sqli")
    f2 = FindingModel(id="f2", scan_id="s1", scanner="Gitleaks", severity="HIGH", title="Secret", file="env", rule="aws-key")
    db_session.add_all([f1, f2])
    db_session.commit()

    trends = dao.get_trend_data(weeks=4)
    assert isinstance(trends, list)

    leaderboard = dao.get_repository_leaderboard()
    assert len(leaderboard) == 1
    assert leaderboard[0]["owner"] == "acme"
    assert leaderboard[0]["risk_score"] == 15  # CRITICAL(10) + HIGH(5)


def test_dao_weekly_stats_and_scanner_usage(db_session):
    """Test get_weekly_stats and get_scanner_usage."""
    dao = DatabaseRepository(db_session)
    repo = dao.get_or_create_repository("org", "repo")
    scan = ScanModel(id="s1", repository_id=repo.id, commit_sha="abc", duration=2.5, started_at=datetime.now(timezone.utc))
    db_session.add(scan)
    db_session.flush()

    f1 = FindingModel(id="f1", scan_id="s1", scanner="Gitleaks", severity="HIGH", title="T1", file="f1", rule="r1")
    db_session.add(f1)
    db_session.commit()

    usage = dao.get_scanner_usage()
    assert usage.get("Gitleaks") == 1

    stats = dao.get_weekly_stats()
    assert stats["scans_this_week"] == 1
    assert stats["findings_this_week"] == 1
