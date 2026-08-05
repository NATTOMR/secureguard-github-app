"""
Purpose: Health check and root informational endpoints.

Responsibilities:
- Provide `GET /` to return basic application metadata.
- Provide `GET /health` to return system health and readiness status.

Dependencies:
- fastapi.APIRouter
- app.core.config.get_settings
- app.schemas.health.HealthResponse, RootResponse

Usage:
    Included in FastAPI app via `api_router`.
"""

from fastapi import APIRouter, Depends, status
from app.core.config import Settings, get_settings
from app.schemas.health import HealthResponse, RootResponse

router = APIRouter()


@router.get(
    "/",
    response_model=RootResponse,
    status_code=status.HTTP_200_OK,
    summary="Root Endpoint",
    description="Returns basic application branding, version, and operational status.",
)
async def root(settings: Settings = Depends(get_settings)) -> RootResponse:
    """Root endpoint returning basic metadata."""
    return RootResponse(
        name=settings.APP_NAME,
        version=settings.APP_VERSION,
        status="operational",
        docs_url="/docs",
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health Check Endpoint",
    description="Returns detailed health checks and system status.",
)
async def health_check(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Health check endpoint for monitoring uptime and status."""
    env_name = "development" if settings.DEBUG else "production"
    return HealthResponse(
        status="healthy",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=env_name,
        checks={"app": "ok", "configuration": "ok"},
    )
