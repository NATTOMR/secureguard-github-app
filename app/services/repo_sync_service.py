"""
Purpose: Sync engine for GitHub App repository discovery.

Responsibilities:
- Fetch all accessible repositories from GitHub via GitHubRepoDiscoveryService.
- Insert newly installed repositories into the database.
- Update metadata for existing repositories.
- Mark uninstalled or deleted repositories as inactive (`is_active=False`).
- Prevent duplicate repository records and maintain strict audit trail.

Dependencies:
- datetime
- sqlalchemy.orm.Session
- sqlalchemy.select
- app.db.session.get_db
- app.db.models.RepositoryModel
- app.github.repo_discovery.GitHubRepoDiscoveryService
- app.auth.github_auth.GitHubAuthManager
- app.core.logging.get_logger
"""

from datetime import datetime, timezone
from typing import Dict, Optional, Set
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.github_auth import GitHubAuthManager
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.models import RepositoryModel
from app.github.repo_discovery import GitHubRepoDiscoveryService

logger = get_logger(__name__)


class RepositorySyncService:
    """Synchronization engine for discovering and updating GitHub repositories."""

    def __init__(
        self,
        auth_manager: Optional[GitHubAuthManager] = None,
        discovery_service: Optional[GitHubRepoDiscoveryService] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.auth_manager = auth_manager or GitHubAuthManager(self.settings)
        self.discovery_service = discovery_service or GitHubRepoDiscoveryService(self.auth_manager)

    async def sync_installation(
        self, installation_id: Optional[int] = None, db: Optional[Session] = None
    ) -> Dict[str, int]:
        """Perform full synchronization of GitHub App installation repositories."""
        if db is None:
            from app.db.session import SessionLocal
            db_session = SessionLocal()
            close_db = True
        else:
            db_session = db
            close_db = False

        try:
            logger.info("Starting repository sync for installation_id: %s", installation_id)
            
            # Step 1: Discover all repos from GitHub REST API
            try:
                discovered_repos = await self.discovery_service.list_installation_repositories(installation_id)
            except Exception as e:
                logger.warning("Failed to fetch GitHub installation repositories directly (%s). Using local/empty sync fallback.", str(e))
                discovered_repos = []

            now = datetime.now(timezone.utc)
            added = 0
            updated = 0
            removed = 0

            # Step 2: Fetch all existing DB repositories
            existing_repos = db_session.execute(select(RepositoryModel)).scalars().all()
            
            # Build lookup maps by github_repository_id and full_name
            repo_by_gh_id: Dict[int, RepositoryModel] = {
                r.github_repository_id: r for r in existing_repos if r.github_repository_id is not None
            }
            repo_by_fullname: Dict[str, RepositoryModel] = {
                f"{r.owner}/{r.name}".lower(): r for r in existing_repos
            }

            discovered_full_names: Set[str] = set()

            # Step 3: Upsert discovered repos
            for disco in discovered_repos:
                gh_id = disco.get("github_repository_id")
                owner = disco.get("owner", "")
                name = disco.get("name", "")
                full_name = disco.get("full_name") or f"{owner}/{name}"
                full_name_lower = full_name.lower()
                discovered_full_names.add(full_name_lower)

                # Match by GitHub ID or full_name
                repo_record: Optional[RepositoryModel] = None
                if gh_id and gh_id in repo_by_gh_id:
                    repo_record = repo_by_gh_id[gh_id]
                elif full_name_lower in repo_by_fullname:
                    repo_record = repo_by_fullname[full_name_lower]

                # Parse ISO dates if string
                pushed_at = disco.get("pushed_at")
                if isinstance(pushed_at, str):
                    try:
                        pushed_at = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    except Exception:
                        pushed_at = None

                if repo_record:
                    # Update existing record
                    repo_record.github_repository_id = gh_id or repo_record.github_repository_id
                    repo_record.owner = owner or repo_record.owner
                    repo_record.name = name or repo_record.name
                    repo_record.full_name = full_name
                    repo_record.private = disco.get("private", repo_record.private)
                    repo_record.visibility = disco.get("visibility", repo_record.visibility)
                    repo_record.default_branch = disco.get("default_branch", repo_record.default_branch)
                    repo_record.language = disco.get("language", repo_record.language)
                    repo_record.size = disco.get("size", repo_record.size)
                    repo_record.archived = disco.get("archived", repo_record.archived)
                    repo_record.disabled = disco.get("disabled", repo_record.disabled)
                    repo_record.html_url = disco.get("html_url", repo_record.html_url)
                    repo_record.clone_url = disco.get("clone_url", repo_record.clone_url)
                    repo_record.is_active = True
                    repo_record.last_sync = now
                    if pushed_at:
                        repo_record.last_push = pushed_at
                    repo_record.updated_at = now
                    updated += 1
                else:
                    # Insert new record
                    new_repo = RepositoryModel(
                        github_repository_id=gh_id,
                        owner=owner,
                        name=name,
                        full_name=full_name,
                        private=disco.get("private", False),
                        visibility=disco.get("visibility", "public"),
                        default_branch=disco.get("default_branch", "main"),
                        language=disco.get("language"),
                        size=disco.get("size", 0),
                        archived=disco.get("archived", False),
                        disabled=disco.get("disabled", False),
                        html_url=disco.get("html_url", f"https://github.com/{owner}/{name}"),
                        clone_url=disco.get("clone_url", f"https://github.com/{owner}/{name}.git"),
                        is_active=True,
                        last_push=pushed_at,
                        last_sync=now,
                        created_at=now,
                        updated_at=now,
                    )
                    db_session.add(new_repo)
                    added += 1

            # Step 4: Mark uninstalled/removed repositories as inactive
            if discovered_repos:
                for r in existing_repos:
                    r_full_name_lower = f"{r.owner}/{r.name}".lower()
                    if r_full_name_lower not in discovered_full_names and r.is_active:
                        r.is_active = False
                        r.last_sync = now
                        r.updated_at = now
                        removed += 1

            db_session.commit()
            logger.info(
                "Repository sync completed. Added: %d, Updated: %d, Removed: %d",
                added, updated, removed
            )
            return {
                "repositories_added": added,
                "repositories_updated": updated,
                "repositories_removed": removed,
            }
        except Exception as e:
            db_session.rollback()
            logger.error("Error during repository synchronization: %s", str(e), exc_info=True)
            raise
        finally:
            if close_db:
                db_session.close()
