"""
Purpose: Structured JSON logging setup for SecureGuard GitHub App.

Responsibilities:
- Configure root logger and uvicorn loggers.
- Format log messages as structured JSON for production readability.
- Expose logger getter utility.

Dependencies:
- logging
- pythonjsonlogger (python-json-logger)
- app.core.config

Usage:
    from app.core.logging import setup_logging, get_logger

    setup_logging()
    logger = get_logger(__name__)
    logger.info("Application starting...")
"""

import logging
import sys
from typing import Optional

try:
    from pythonjsonlogger import jsonlog
    JSON_LOGGER_AVAILABLE = True
except ImportError:
    JSON_LOGGER_AVAILABLE = False

from app.core.config import get_settings


def setup_logging(log_level: Optional[str] = None) -> None:
    """Configure system-wide structured logging."""
    settings = get_settings()
    level_str = log_level or settings.LOG_LEVEL
    level = getattr(logging, level_str.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove pre-existing handlers to prevent duplicated logs
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(level)

    if JSON_LOGGER_AVAILABLE:
        formatter = jsonlog.JsonFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(module)s %(funcName)s %(message)s",
            rename_fields={"asctime": "timestamp", "levelname": "level", "funcName": "function"},
        )
    else:
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s:%(funcName)s] %(message)s"
        )

    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    # Mute noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance."""
    return logging.getLogger(name)
