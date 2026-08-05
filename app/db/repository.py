"""
Purpose: Data Access Object (DAO) Repository pattern for database persistence.

Responsibilities:
- Perform CRUD operations for Repositories, Scans, Findings, and Webhook Events.
- Provide helper methods to persist incoming scan results into database tables.

Dependencies:
- sqlalchemy.orm.Session
- sqlalchemy.select, func, desc
- app.db.models.RepositoryModel, ScanModel, FindingModel, EventModel
- app.models.scan_result.ScanResult

Usage:
    dao = DatabaseRepository(db)
    repo = dao.get_or_create_repository("octocat", "Hello-World")
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.models import EventModel, FindingModel, RepositoryModel, ScanModel
from app.models.scan_result import ScanResult


class DatabaseRepository:
    """DAO for SecureGuard database tables."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_or_create_repository(self, owner: str, name: str, default_branch: str = "main") -> RepositoryModel:
        """Fetch existing repository or create a new database record."""
        stmt = select(RepositoryModel).where(
            RepositoryModel.owner == owner, RepositoryModel.name == name
        )
        repo = self.db.execute(stmt).scalar_one_or_none()
        if not repo:
            repo = RepositoryModel(
                owner=owner,
                name=name,
                default_branch=default_branch,
                created_at=datetime.now(timezone.utc),
            )
            self.db.add(repo)
            self.db.commit()
            self.db.refresh(repo)
        return repo

    def save_scan_result(
        self,
        owner: str,
        repo_name: str,
        commit_sha: str,
        scan_result: ScanResult,
        branch: str = "main",
        trigger: str = "push",
    ) -> ScanModel:
        """Persist ScanResult and its Finding models to the database."""
        repo = self.get_or_create_repository(owner, repo_name, default_branch=branch)

        scan = ScanModel(
            id=scan_result.scan_id,
            repository_id=repo.id,
            commit_sha=commit_sha,
            branch=branch,
            trigger=trigger,
            status="completed",
            started_at=scan_result.timestamp,
            finished_at=datetime.now(timezone.utc),
            duration=1.5,
        )
        self.db.add(scan)
        self.db.flush()

        for f in scan_result.findings:
            finding = FindingModel(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                scanner=f.scanner_name or "Gitleaks",
                severity=f.severity.upper(),
                title=f.title,
                description=f.description,
                file=f.file_path,
                line=f.line_number,
                rule=f.rule_id,
                recommendation=f.recommendation,
                cwe="CWE-798" if f.scanner_name == "Gitleaks" else "CWE-20",
                owasp="A07:2021-Identification and Authentication Failures",
                cvss=8.5 if f.severity.upper() in ("CRITICAL", "HIGH") else 5.0,
                status="open",
            )
            self.db.add(finding)

        self.db.commit()
        self.db.refresh(scan)
        return scan

    def record_event(self, owner: Optional[str], repo_name: Optional[str], event: str, delivery_id: Optional[str]) -> EventModel:
        """Record a webhook delivery event."""
        repo_id = None
        if owner and repo_name:
            repo = self.get_or_create_repository(owner, repo_name)
            repo_id = repo.id

        evt = EventModel(
            id=str(uuid.uuid4()),
            repository_id=repo_id,
            event=event,
            delivery_id=delivery_id,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(evt)
        self.db.commit()
        self.db.refresh(evt)
        return evt

    def get_dashboard_overview(self) -> Dict[str, Any]:
        """Aggregate high-level overview metrics for the main dashboard page."""
        total_repos = self.db.execute(select(func.count(RepositoryModel.id))).scalar() or 0
        total_scans = self.db.execute(select(func.count(ScanModel.id))).scalar() or 0

        # Severity counts
        crit_cnt = self.db.execute(select(func.count(FindingModel.id)).where(FindingModel.severity == "CRITICAL")).scalar() or 0
        high_cnt = self.db.execute(select(func.count(FindingModel.id)).where(FindingModel.severity == "HIGH")).scalar() or 0
        med_cnt = self.db.execute(select(func.count(FindingModel.id)).where(FindingModel.severity == "MEDIUM")).scalar() or 0
        low_cnt = self.db.execute(select(func.count(FindingModel.id)).where(FindingModel.severity == "LOW")).scalar() or 0

        # Secrets vs SAST scanner counts
        secrets_cnt = self.db.execute(select(func.count(FindingModel.id)).where(FindingModel.scanner == "Gitleaks")).scalar() or 0
        sast_cnt = self.db.execute(select(func.count(FindingModel.id)).where(FindingModel.scanner == "Semgrep")).scalar() or 0

        # Latest scans
        latest_scans_stmt = (
            select(ScanModel)
            .order_by(desc(ScanModel.started_at))
            .limit(5)
        )
        latest_scans = self.db.execute(latest_scans_stmt).scalars().all()

        # Recent events
        events_stmt = (
            select(EventModel)
            .order_by(desc(EventModel.created_at))
            .limit(5)
        )
        events = self.db.execute(events_stmt).scalars().all()

        return {
            "total_repositories": total_repos,
            "total_scans": total_scans,
            "critical_findings": crit_cnt,
            "high_findings": high_cnt,
            "medium_findings": med_cnt,
            "low_findings": low_cnt,
            "secrets_count": secrets_cnt,
            "sast_count": sast_cnt,
            "latest_scans": [
                {
                    "id": s.id,
                    "repo": f"{s.repository.owner}/{s.repository.name}" if s.repository else "unknown",
                    "commit": s.commit_sha[:7],
                    "branch": s.branch,
                    "status": s.status,
                    "findings_count": len(s.findings),
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                }
                for s in latest_scans
            ],
            "recent_events": [
                {
                    "id": e.id,
                    "event": e.event,
                    "delivery_id": e.delivery_id,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in events
            ],
        }
