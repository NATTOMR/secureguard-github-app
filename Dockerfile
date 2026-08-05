# ==========================================
# SecureGuard GitHub App — Production Dockerfile
# ==========================================
# Multi-stage build for security, minimal size, and performance.

# ── Stage 1: Build Dependencies ────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies
COPY requirements.txt .

# Install wheels
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Final Runtime Image ───────────────
FROM python:3.11-slim AS runner

# Create non-root system user for container security
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/sh -m appuser

WORKDIR /app

# Copy installed dependencies from builder stage
COPY --from=builder /install /usr/local

# Copy application source code
COPY app/ ./app/
COPY README.md .

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

USER appuser

# Expose FastAPI port
EXPOSE 8000

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# Launch Uvicorn ASGI server
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
