"""
Purpose: Main application factory and FastAPI entry point.

Responsibilities:
- Initialize FastAPI application with settings, lifespan handlers, and middleware.
- Register global API router.
- Configure CORS and loggers on startup.

Dependencies:
- contextlib.asynccontextmanager
- fastapi.FastAPI
- fastapi.middleware.cors.CORSMiddleware
- app.api.router.api_router
- app.core.config.get_settings
- app.core.logging.setup_logging, get_logger

Usage:
    uvicorn app.main:app --reload
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.logging import get_logger, setup_logging

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager handling startup and shutdown events."""
    settings = get_settings()
    setup_logging(settings.LOG_LEVEL)
    logger.info("Initializing %s v%s...", settings.APP_NAME, settings.APP_VERSION)
    yield
    logger.info("Shutting down %s...", settings.APP_NAME)


def create_app() -> FastAPI:
    """FastAPI Application Factory."""
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Automated Security Analysis GitHub App for Secret Detection and SAST Scanning.",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS (Restrictive by default)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.DEBUG else [],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Attach router
    app.include_router(api_router)

    return app


app = create_app()
