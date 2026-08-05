"""
Purpose: GitHub Checks API REST client service.

Responsibilities:
- Create Check Runs (POST /repos/{owner}/{repo}/check-runs) with queued or in_progress status.
- Update Check Runs (PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}) with completed status, conclusion, output, and annotations.
- Provide automatic retry logic for transient API failures.

Dependencies:
- httpx
- asyncio
- typing.Dict, Any, Optional
- app.core.logging.get_logger
- app.core.exceptions.GitHubAPIError

Usage:
    checks_service = GitHubChecksService()
    check_id = await checks_service.create_check_run(
        owner="octocat", repo="Hello-World", head_sha="7fd1a60b", name="SecureGuard Scan", token="ghs_..."
    )
    await checks_service.update_check_run(
        owner="octocat", repo="Hello-World", check_run_id=check_id, token="ghs_...", status="completed", conclusion="success"
    )
"""

import asyncio
from typing import Any, Dict, Optional
import httpx

from app.core.exceptions import GitHubAPIError
from app.core.logging import get_logger

logger = get_logger(__name__)


class GitHubChecksService:
    """Service interacting directly with GitHub REST API Checks Endpoints."""

    GITHUB_API_URL = "https://api.github.com"
    MAX_RETRIES = 3

    async def create_check_run(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        name: str,
        token: str,
        status: str = "queued",
    ) -> int:
        """Create a new Check Run for a commit (returns check_run_id)."""
        url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/check-runs"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        payload = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }

        logger.info("Creating Check Run '%s' (%s) for %s/%s at %s", name, status, owner, repo, head_sha)

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(url, headers=headers, json=payload, timeout=30.0)
                    if response.status_code in (200, 201):
                        data = response.json()
                        check_run_id = data["id"]
                        logger.info("Check Run created successfully with ID %d", check_run_id)
                        return check_run_id
                    
                    logger.warning(
                        "Attempt %d/%d to create Check Run returned status %d: %s",
                        attempt, self.MAX_RETRIES, response.status_code, response.text
                    )
            except Exception as e:
                logger.warning("Attempt %d/%d creating Check Run failed: %s", attempt, self.MAX_RETRIES, str(e))

            if attempt < self.MAX_RETRIES:
                await asyncio.sleep(1.0 * attempt)

        raise GitHubAPIError(f"Failed to create GitHub Check Run on {owner}/{repo}")

    async def update_check_run(
        self,
        owner: str,
        repo: str,
        check_run_id: int,
        token: str,
        status: Optional[str] = None,
        conclusion: Optional[str] = None,
        output: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update an existing Check Run with status, conclusion, output, and annotations."""
        url = f"{self.GITHUB_API_URL}/repos/{owner}/{repo}/check-runs/{check_run_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        payload: Dict[str, Any] = {}
        if status:
            payload["status"] = status
        if conclusion:
            payload["conclusion"] = conclusion
        if output:
            payload["output"] = output

        logger.info(
            "Updating Check Run #%d for %s/%s (status=%s, conclusion=%s)",
            check_run_id, owner, repo, status, conclusion
        )

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.patch(url, headers=headers, json=payload, timeout=30.0)
                    if response.status_code in (200, 201):
                        logger.info("Successfully updated Check Run #%d", check_run_id)
                        return response.json()
                    
                    logger.warning(
                        "Attempt %d/%d to update Check Run #%d returned status %d: %s",
                        attempt, self.MAX_RETRIES, check_run_id, response.status_code, response.text
                    )
            except Exception as e:
                logger.warning("Attempt %d/%d updating Check Run #%d failed: %s", attempt, self.MAX_RETRIES, check_run_id, str(e))

            if attempt < self.MAX_RETRIES:
                await asyncio.sleep(1.0 * attempt)

        raise GitHubAPIError(f"Failed to update GitHub Check Run #{check_run_id} on {owner}/{repo}")
