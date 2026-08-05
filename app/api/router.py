"""
Purpose: Main API router aggregating all endpoints.

Responsibilities:
- Combine health, webhook, and auth routes into unified API router.

Dependencies:
- fastapi.APIRouter
- app.api.routes.health
- app.api.routes.webhook
- app.api.routes.auth

Usage:
    from app.api.router import api_router

    app.include_router(api_router)
"""

from fastapi import APIRouter
from app.api.routes import ai, auth, dashboard, health, scan, webhook

api_router = APIRouter()

# Include health routes at root level (/ and /health)
api_router.include_router(health.router)

# Include webhook route at /webhook
api_router.include_router(webhook.router)

# Include authentication routes at /auth/status and /auth/test
api_router.include_router(auth.router)

# Include scanning routes at /scan
api_router.include_router(scan.router)

# Include dashboard API routes at /api
api_router.include_router(dashboard.router)

# Include AI Assistant routes at /api/ai
api_router.include_router(ai.router)
