"""
Purpose: Automated tests for Phase 3 export endpoints (/api/export/sarif, /pdf, /html).
"""

import pytest


def test_export_sarif_latest(client):
    """Test GET /api/export/sarif/latest endpoint."""
    res = client.get("/api/export/sarif/latest")
    assert res.status_code == 200
    assert "application/json" in res.headers["content-type"]
    sarif = res.json()
    assert sarif["version"] == "2.1.0"


def test_export_pdf_latest(client):
    """Test GET /api/export/pdf/latest endpoint."""
    res = client.get("/api/export/pdf/latest")
    assert res.status_code == 200
    assert len(res.content) > 0


def test_export_html_latest(client):
    """Test GET /api/export/html/latest endpoint."""
    res = client.get("/api/export/html/latest")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "SecureGuard" in res.text
