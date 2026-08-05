"""
Purpose: Test suite for SQLAlchemy 2.0 ORM models and DatabaseRepository DAO.

Responsibilities:
- Test repository creation and retrieval.
- Test scan result and finding persistence.
- Test webhook event logging.
- Test dashboard overview statistics calculation.

Dependencies:
- pytest
- sqlalchemy.create_engine, sessionmaker
- app.db.base.Base
- app.db.repository.DatabaseRepository
- app.models.scan_result.ScanResult, Finding

Usage:
    pytest tests/test_database.py -v
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.repository import DatabaseRepository
from app.models.scan_result import Finding, ScanResult


@pytest.fixture
def db_session():
    """Create in-memory SQLite database session for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_get_or_create_repository(db_session):
    """Test get_or_create_repository creates and retrieves repository."""
    dao = DatabaseRepository(db_session)
    repo1 = dao.get_or_create_repository("octocat", "Hello-World")
    assert repo1.id is not None
    assert repo1.owner == "octocat"
    assert repo1.name == "Hello-World"

    repo2 = dao.get_or_create_repository("octocat", "Hello-World")
    assert repo2.id == repo1.id


def test_save_scan_result_and_findings(db_session):
    """Test saving ScanResult and Finding models to database."""
    dao = DatabaseRepository(db_session)
    findings = [
        Finding(
            rule_id="aws-access-key",
            title="Leaked AWS Key",
            severity="CRITICAL",
            file_path="aws.py",
            line_number=10,
            description="Exposed AWS credential",
            recommendation="Revoke key",
            scanner_name="Gitleaks",
        )
    ]
    scan_result = ScanResult(
        scan_id="scan-db-1",
        repository="octocat/Hello-World",
        commit_sha="7fd1a60b",
        timestamp=datetime.now(timezone.utc),
        findings=findings,
    )

    scan_model = dao.save_scan_result("octocat", "Hello-World", "7fd1a60b", scan_result)
    assert scan_model.id == "scan-db-1"
    assert len(scan_model.findings) == 1
    assert scan_model.findings[0].severity == "CRITICAL"


def test_dashboard_overview_stats(db_session):
    """Test dashboard statistics aggregation."""
    dao = DatabaseRepository(db_session)
    stats = dao.get_dashboard_overview()
    assert "total_repositories" in stats
    assert "total_scans" in stats
    assert "critical_findings" in stats
