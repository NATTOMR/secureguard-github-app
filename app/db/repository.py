"""
Purpose: Data Access Object (DAO) Repository pattern for database persistence.

Responsibilities:
- Perform CRUD operations for Repositories, Scans, Findings, and Webhook Events.
- Provide helper methods to persist incoming scan results into database tables.
- Supply analytics queries for dashboard trends, leaderboards, and weekly stats.
- Manage GitHub Issue records linked to security findings.

Dependencies:
- sqlalchemy.orm.Session
- sqlalchemy.select, func, desc
- app.db.models.RepositoryModel, ScanModel, FindingModel, EventModel, GitHubIssueModel
- app.models.scan_result.ScanResult

Usage:
    dao = DatabaseRepository(db)
    repo = dao.get_or_create_repository("octocat", "Hello-World")
"""

from datetime import datetime, timezone, timedelta
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import case, desc, func, select
from sqlalchemy.orm import Session

from app.db.models import EventModel, FindingModel, GitHubIssueModel, IntegrationEventModel, RepositoryModel, ScanModel
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

    # ------------------------------------------------------------------
    # Phase 3 – Analytics & GitHub Issue Management
    # ------------------------------------------------------------------

    def get_scan_history(
        self,
        limit: int = 20,
        offset: int = 0,
        repo_id: Optional[int] = None,
        status: Optional[str] = None,
    ) -> List[ScanModel]:
        """Return a paginated list of scans with optional repository and status filters."""
        stmt = select(ScanModel)
        if repo_id is not None:
            stmt = stmt.where(ScanModel.repository_id == repo_id)
        if status is not None:
            stmt = stmt.where(ScanModel.status == status)
        stmt = stmt.order_by(desc(ScanModel.started_at)).limit(limit).offset(offset)
        return list(self.db.execute(stmt).scalars().all())

    def get_trend_data(self, weeks: int = 12) -> List[Dict[str, Any]]:
        """Calculate weekly finding counts grouped by severity over the last *weeks* weeks.

        Returns a list of dicts with keys: week_start, critical, high, medium, low.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(weeks=weeks)

        # Join findings → scans to access started_at for date bucketing
        rows = (
            self.db.execute(
                select(
                    ScanModel.started_at,
                    FindingModel.severity,
                )
                .join(FindingModel, FindingModel.scan_id == ScanModel.id)
                .where(ScanModel.started_at >= cutoff)
            )
            .all()
        )

        # Bucket findings into ISO-week buckets keyed by Monday date
        buckets: Dict[str, Dict[str, int]] = {}
        for started_at, severity in rows:
            if started_at is None:
                continue
            # Compute the Monday of the ISO week
            week_start = (started_at - timedelta(days=started_at.weekday())).date()
            key = week_start.isoformat()
            if key not in buckets:
                buckets[key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            sev_key = severity.lower() if severity else "low"
            if sev_key in buckets[key]:
                buckets[key][sev_key] += 1

        # Build ordered result list
        result: List[Dict[str, Any]] = []
        for week_key in sorted(buckets.keys()):
            entry = {"week_start": week_key}
            entry.update(buckets[week_key])
            result.append(entry)

        return result

    def get_repository_leaderboard(self) -> List[Dict[str, Any]]:
        """Rank repositories by a weighted risk score.

        Weights: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1.
        Returns dicts with: id, owner, name, risk_score, total_findings, critical_count.
        """
        risk_score_expr = func.sum(
            case(
                (FindingModel.severity == "CRITICAL", 10),
                (FindingModel.severity == "HIGH", 5),
                (FindingModel.severity == "MEDIUM", 2),
                (FindingModel.severity == "LOW", 1),
                else_=0,
            )
        )
        critical_count_expr = func.sum(
            case(
                (FindingModel.severity == "CRITICAL", 1),
                else_=0,
            )
        )

        stmt = (
            select(
                RepositoryModel.id,
                RepositoryModel.owner,
                RepositoryModel.name,
                risk_score_expr.label("risk_score"),
                func.count(FindingModel.id).label("total_findings"),
                critical_count_expr.label("critical_count"),
            )
            .join(ScanModel, ScanModel.repository_id == RepositoryModel.id)
            .join(FindingModel, FindingModel.scan_id == ScanModel.id)
            .group_by(RepositoryModel.id, RepositoryModel.owner, RepositoryModel.name)
            .order_by(desc("risk_score"))
        )

        rows = self.db.execute(stmt).all()
        return [
            {
                "id": row.id,
                "owner": row.owner,
                "name": row.name,
                "risk_score": int(row.risk_score or 0),
                "total_findings": int(row.total_findings or 0),
                "critical_count": int(row.critical_count or 0),
            }
            for row in rows
        ]

    def get_scanner_usage(self) -> Dict[str, int]:
        """Return a mapping of scanner name → total finding count."""
        stmt = (
            select(FindingModel.scanner, func.count(FindingModel.id).label("count"))
            .group_by(FindingModel.scanner)
        )
        rows = self.db.execute(stmt).all()
        return {row.scanner: int(row.count) for row in rows}

    def get_weekly_stats(self) -> Dict[str, Any]:
        """Compute aggregate statistics for the last 7 days.

        Returns: scans_this_week, findings_this_week, new_repos_this_week, avg_scan_duration.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)

        scans_this_week = (
            self.db.execute(
                select(func.count(ScanModel.id)).where(ScanModel.started_at >= cutoff)
            ).scalar()
            or 0
        )

        findings_this_week = (
            self.db.execute(
                select(func.count(FindingModel.id))
                .join(ScanModel, ScanModel.id == FindingModel.scan_id)
                .where(ScanModel.started_at >= cutoff)
            ).scalar()
            or 0
        )

        new_repos_this_week = (
            self.db.execute(
                select(func.count(RepositoryModel.id)).where(RepositoryModel.created_at >= cutoff)
            ).scalar()
            or 0
        )

        avg_duration = (
            self.db.execute(
                select(func.avg(ScanModel.duration)).where(ScanModel.started_at >= cutoff)
            ).scalar()
        )

        return {
            "scans_this_week": int(scans_this_week),
            "findings_this_week": int(findings_this_week),
            "new_repos_this_week": int(new_repos_this_week),
            "avg_scan_duration": round(float(avg_duration), 2) if avg_duration is not None else 0.0,
        }

    def get_common_vulnerabilities(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the most frequently occurring rule_ids with count and example metadata.

        Keys: rule, count, severity, scanner.
        """
        stmt = (
            select(
                FindingModel.rule,
                func.count(FindingModel.id).label("count"),
                func.min(FindingModel.severity).label("severity"),
                func.min(FindingModel.scanner).label("scanner"),
            )
            .group_by(FindingModel.rule)
            .order_by(desc("count"))
            .limit(limit)
        )
        rows = self.db.execute(stmt).all()
        return [
            {
                "rule": row.rule,
                "count": int(row.count),
                "severity": row.severity,
                "scanner": row.scanner,
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # GitHub Issue Record Management
    # ------------------------------------------------------------------

    def create_github_issue_record(
        self, finding_id: str, issue_number: int, issue_url: str
    ) -> GitHubIssueModel:
        """Create a new GitHub Issue tracking record linked to a finding."""
        issue = GitHubIssueModel(
            finding_id=finding_id,
            issue_number=issue_number,
            issue_url=issue_url,
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(issue)
        self.db.commit()
        self.db.refresh(issue)
        return issue

    def get_github_issues(
        self, status: Optional[str] = None, limit: int = 50
    ) -> List[GitHubIssueModel]:
        """List GitHub Issue records with optional status filter."""
        stmt = select(GitHubIssueModel)
        if status is not None:
            stmt = stmt.where(GitHubIssueModel.status == status)
        stmt = stmt.order_by(desc(GitHubIssueModel.created_at)).limit(limit)
        return list(self.db.execute(stmt).scalars().all())

    def get_github_issue_by_id(self, issue_id: int) -> Optional[GitHubIssueModel]:
        """Retrieve a single GitHub Issue record by its primary key."""
        stmt = select(GitHubIssueModel).where(GitHubIssueModel.id == issue_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def issue_exists_for_finding(self, finding_id: str) -> bool:
        """Check whether a GitHub Issue record already exists for a given finding."""
        stmt = select(func.count(GitHubIssueModel.id)).where(
            GitHubIssueModel.finding_id == finding_id
        )
        count = self.db.execute(stmt).scalar() or 0
        return count > 0

    def get_average_scan_duration(self) -> float:
        """Return the average scan duration across all scans with a recorded duration."""
        avg = self.db.execute(
            select(func.avg(ScanModel.duration)).where(ScanModel.duration.isnot(None))
        ).scalar()
        return round(float(avg), 2) if avg is not None else 0.0

    def record_integration_event(
        self,
        connector: str,
        status: str,
        repository: Optional[str] = None,
        scan_id: Optional[str] = None,
        response: Optional[str] = None,
    ) -> IntegrationEventModel:
        """Record an outbound SOC integration dispatch event."""
        evt = IntegrationEventModel(
            id=str(uuid.uuid4()),
            connector=connector,
            status=status,
            repository=repository,
            scan_id=scan_id,
            response=response,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(evt)
        self.db.commit()
        self.db.refresh(evt)
        return evt

    def get_integration_events(
        self, connector: Optional[str] = None, limit: int = 50
    ) -> List[IntegrationEventModel]:
        """List recorded integration events with optional connector filter."""
        stmt = select(IntegrationEventModel)
        if connector:
            stmt = stmt.where(IntegrationEventModel.connector == connector)
        stmt = stmt.order_by(desc(IntegrationEventModel.created_at)).limit(limit)
        return list(self.db.execute(stmt).scalars().all())

