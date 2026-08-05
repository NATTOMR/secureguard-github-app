# SecureGuard Architecture Documentation

## Purpose
This document details the architectural layout, component design, data flow, and security model of the **SecureGuard GitHub App**.

## Component Overview

```
                      +---------------------------+
                      |   GitHub Webhook Event    |
                      +---------------------------+
                                    |
                                    v
                      +---------------------------+
                      |    FastAPI Webhook Route  |
                      |  (Signature Verification) |
                      +---------------------------+
                                    |
                                    v
                      +---------------------------+
                      |      Scan Orchestrator    |
                      +---------------------------+
                        /                       \
                       v                         v
        +-----------------------+       +-----------------------+
        |   Gitleaks Scanner    |       |    Semgrep Scanner    |
        |   (Secret Detection)  |       |       (SAST)          |
        +-----------------------+       +-----------------------+
                       \                         /
                        v                       v
                      +---------------------------+
                      |     Scan Result Model     |
                      +---------------------------+
                                    |
                                    v
                      +---------------------------+
                      |   GitHub API Reporting    |
                      |  (PR Comment / Issue)     |
                      +---------------------------+
```

## Core Modules

### 1. `app/core/`
- **`config.py`**: Configuration management powered by Pydantic Settings v2. Reads configuration from `.env` files and environment variables.
- **`logging.py`**: Configures system-wide JSON structured logging.

### 2. `app/api/`
- **`router.py`**: Top-level API router.
- **`routes/health.py`**: Provides `/` and `/health` endpoints.
- **`routes/webhook.py`**: Handles incoming GitHub webhook POST requests.

### 3. `app/auth/`
- **`github_auth.py`**: Generates RS256-signed JWTs using GitHub App ID & private key, and exchanges JWTs for installation access tokens.

### 4. `app/scanners/`
- **`base.py`**: `BaseScanner` abstract class contract.
- **`gitleaks.py`**: Gitleaks secret scanner runner.
- **`semgrep.py`**: Semgrep SAST scanner runner.

### 5. `app/services/`
- **`scan_service.py`**: Manages scanning workflow and aggregates findings into standard domain objects.
