import json
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.security import verify_webhook_signature
from app.schemas.webhook import WebhookAckResponse
from app.api.routes.scan import get_scan_service, get_notification_service
from app.services.scan_service import ScanService
from app.services.notification_service import GitHubNotificationService

logger = get_logger(__name__)

router = APIRouter()


async def process_webhook_event(
    event_type: str,
    payload: dict,
    scan_service: ScanService,
    notification_service: GitHubNotificationService,
) -> None:
    """Background task handler for processing push and pull_request events."""
    try:
        installation_id = payload.get("installation", {}).get("id")
        repo_data = payload.get("repository", {})
        owner = repo_data.get("owner", {}).get("login")
        repo = repo_data.get("name")

        if not owner or not repo:
            logger.warning("Webhook payload missing owner or repository name.")
            return

        commit_sha = None
        pr_number = None

        if event_type == "push":
            commit_sha = payload.get("after")
            # Ignore zero commit (branch deletion)
            if not commit_sha or commit_sha == "0000000000000000000000000000000000000000":
                logger.info("Ignoring push event for branch deletion.")
                return

        elif event_type == "pull_request":
            action = payload.get("action")
            if action not in ("opened", "synchronize", "reopened"):
                logger.info("Ignoring pull_request action '%s' (only opened, synchronize, reopened are processed).", action)
                return
            pr_data = payload.get("pull_request", {})
            head_ref = pr_data.get("head", {}).get("ref", "")
            commit_sha = pr_data.get("head", {}).get("sha")
            pr_number = pr_data.get("number")

            if not owner or not repo or not pr_number or not commit_sha:
                logger.warning("Missing required PR details in webhook payload.")
                return

            logger.info("Executing PR scan & review bot for %s/%s PR #%d (action: %s)", owner, repo, pr_number, action)
            from app.services.pr_scan_service import PRScanService
            from app.github.pr_review_service import PRReviewService
            from app.services.check_run_service import CheckRunService

            check_service = CheckRunService()
            check_run_id = None
            if scan_service.auth_manager and installation_id:
                try:
                    token = await scan_service.auth_manager.get_installation_token(installation_id)
                    check_run_id = await check_service.checks_service.create_check_run(
                        owner=owner, repo=repo, head_sha=commit_sha, name="SecureGuard Security Scan", token=token, status="in_progress"
                    )
                except Exception as ce:
                    logger.warning("Could not initialize Check Run: %s", str(ce))

            pr_scan_service = PRScanService(auth_manager=scan_service.auth_manager)
            pr_review_service = PRReviewService()

            pr_result = await pr_scan_service.scan_pull_request(
                owner=owner,
                repo=repo,
                pr_number=pr_number,
                head_ref=head_ref,
                head_sha=commit_sha,
                installation_id=installation_id,
            )
            report_md = pr_review_service.generate_pr_markdown_report(pr_result)

            from app.db.session import SessionLocal
            from app.db.repository import DatabaseRepository
            try:
                with SessionLocal() as db:
                    dao = DatabaseRepository(db)
                    dao.save_scan_result(owner, repo, commit_sha, pr_result, branch=head_ref, trigger="pull_request")
            except Exception as dbe:
                logger.warning("Could not persist PR scan result to DB: %s", str(dbe))

            if scan_service.auth_manager and installation_id:
                try:
                    token = await scan_service.auth_manager.get_installation_token(installation_id)
                    await check_service.publish_scan_checks(owner, repo, commit_sha, pr_result, token, check_run_id=check_run_id)
                    await pr_review_service.post_or_update_pr_comment(owner, repo, pr_number, report_md, token)
                except Exception as pe:
                    logger.error("Failed to update PR checks / comment on PR #%d: %s", pr_number, str(pe))
            return

        if not commit_sha:
            logger.warning("Could not determine target commit SHA from webhook event.")
            return

        logger.info("Automated webhook scan starting for %s/%s at commit %s", owner, repo, commit_sha)
        
        # 1. Run Gitleaks pipeline (clone -> scan -> summarize -> cleanup)
        pipeline_report = await scan_service.run_gitleaks_pipeline(
            owner=owner, repo=repo, commit_sha=commit_sha, installation_id=installation_id
        )

        # 2. Execute dual scan for PR/Check runs
        scan_result = await scan_service.execute_scan(
            owner=owner,
            repo=repo,
            commit_sha=commit_sha,
            installation_id=installation_id,
        )

        from app.db.session import SessionLocal
        from app.db.repository import DatabaseRepository
        try:
            with SessionLocal() as db:
                dao = DatabaseRepository(db)
                dao.save_scan_result(owner, repo, commit_sha, scan_result, trigger="push")
        except Exception as dbe:
            logger.warning("Could not persist push scan result to DB: %s", str(dbe))

        # 3. Publish Check Run
        from app.services.check_run_service import CheckRunService
        check_service = CheckRunService()
        if scan_service.auth_manager and installation_id:
            try:
                token = await scan_service.auth_manager.get_installation_token(installation_id)
                await check_service.publish_scan_checks(owner, repo, commit_sha, scan_result, token)
            except Exception as ce:
                logger.error("Failed to publish Check Run for push event: %s", str(ce))

        # 4. If secrets found, create GitHub Issue
        if pipeline_report.get("findings") and len(pipeline_report["findings"]) > 0:
            from app.services.github_issue_service import GitHubIssueService
            issue_service = GitHubIssueService()
            auth_manager = scan_service.auth_manager
            if auth_manager and installation_id:
                try:
                    token = await auth_manager.get_installation_token(installation_id)
                    await issue_service.create_security_issue(owner, repo, pipeline_report, token)
                except Exception as ie:
                    logger.error("Failed to create issue from pipeline report: %s", str(ie))

        # 5. Notify GitHub (PR comments / commit comments)
        await notification_service.notify(
            scan_result=scan_result,
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            installation_id=installation_id,
        )

    except Exception as e:
        logger.error("Error processing webhook background task: %s", str(e), exc_info=True)


@router.post(
    "/webhook",
    response_model=WebhookAckResponse,
    status_code=status.HTTP_200_OK,
    summary="GitHub Webhook Listener",
    description="Receives and processes GitHub webhook events (push, pull_request) with signature verification.",
)
async def handle_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_github_delivery: Optional[str] = Header(None, alias="X-GitHub-Delivery"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    settings: Settings = Depends(get_settings),
    scan_service: ScanService = Depends(get_scan_service),
    notification_service: GitHubNotificationService = Depends(get_notification_service),
) -> WebhookAckResponse:
    """Handle incoming GitHub Webhook HTTP POST request."""
    body_bytes = await request.body()

    # Verify signature
    if settings.GITHUB_WEBHOOK_SECRET:
        if not verify_webhook_signature(body_bytes, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET):
            logger.warning("Invalid webhook signature for delivery %s", x_github_delivery)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature",
            )

    try:
        payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
    except Exception:
        payload = {}

    # Dispatch repository discovery sync for installation events
    if x_github_event in ("installation", "installation_repositories"):
        installation_id = payload.get("installation", {}).get("id")
        from app.services.repo_sync_service import RepositorySyncService
        sync_service = RepositorySyncService()
        background_tasks.add_task(sync_service.sync_installation, installation_id)
        msg = f"Webhook '{x_github_event}' queued for repository synchronization"

    # Dispatch to background task if event is push or pull_request
    elif x_github_event in ("push", "pull_request"):
        background_tasks.add_task(
            process_webhook_event,
            x_github_event,
            payload,
            scan_service,
            notification_service,
        )
        msg = f"Webhook '{x_github_event}' queued for scanning"
    else:
        msg = f"Webhook '{x_github_event}' received (ignored)"

    logger.info("Webhook %s processed: %s", x_github_delivery, msg)
    return WebhookAckResponse(
        status="received",
        event=x_github_event,
        delivery_id=x_github_delivery,
    )
