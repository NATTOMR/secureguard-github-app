"""
Purpose: Service for generating enterprise HTML and PDF security reports.

Responsibilities:
- Build HTML report summarizing scan details, findings, OWASP/MITRE mappings, risk posture, and AI remediation suggestions.
- Render downloadable PDF/HTML reports for export endpoints.

Dependencies:
- jinja2 or string formatting for HTML generation
- app.db.models.ScanModel, FindingModel
- app.core.logging.get_logger

Usage:
    from app.services.pdf_report_service import PDFReportService

    service = PDFReportService()
    html_content = service.generate_html_report(scan)
    pdf_bytes = service.generate_pdf_report(scan)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import html

from app.core.logging import get_logger
from app.db.models import FindingModel, ScanModel

logger = get_logger(__name__)


class PDFReportService:
    """Generates enterprise HTML and PDF security reports from scan results."""

    def generate_html_report(self, scan: ScanModel) -> str:
        """Generate a complete standalone enterprise HTML security report."""
        repo_name = f"{scan.repository.owner}/{scan.repository.name}" if scan.repository else "Unknown Repo"
        findings = list(scan.findings)

        crit_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity.upper() == "HIGH")
        med_count = sum(1 for f in findings if f.severity.upper() == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity.upper() in ("LOW", "INFO"))

        # Risk score calculation
        raw_score = (crit_count * 10) + (high_count * 5) + (med_count * 2) + low_count
        risk_score = min(raw_score, 100)
        risk_level = "CRITICAL" if risk_score >= 50 else ("HIGH" if risk_score >= 25 else ("MEDIUM" if risk_score >= 10 else "LOW"))

        findings_rows = ""
        for idx, f in enumerate(findings, 1):
            sev_class = f.severity.lower()
            findings_rows += f"""
            <tr>
                <td>{idx}</td>
                <td><span class="badge badge-{sev_class}">{html.escape(f.severity)}</span></td>
                <td><strong>{html.escape(f.title)}</strong><br><small style="color: #64748b;">Rule: {html.escape(f.rule)}</small></td>
                <td><code>{html.escape(f.file)}:{f.line or 'N/A'}</code></td>
                <td>{html.escape(f.scanner)}</td>
                <td>{html.escape(f.cwe or 'N/A')}</td>
                <td>{html.escape(f.owasp or 'N/A')}</td>
            </tr>
            """

        if not findings_rows:
            findings_rows = '<tr><td colspan="7" style="text-align: center; color: #10b981; padding: 2rem;">No security vulnerabilities detected. Excellent security posture!</td></tr>'

        top_findings_detail = ""
        top_findings = sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.severity.upper(), 4))[:5]
        for f in top_findings:
            sev_class = f.severity.lower()
            recommendation = f.recommendation or f.description or "Review and patch vulnerable code pattern."
            top_findings_detail += f"""
            <div class="card" style="border-left: 4px solid var(--sev-{sev_class}, #64748b); margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0;">{html.escape(f.title)}</h3>
                    <span class="badge badge-{sev_class}">{html.escape(f.severity)}</span>
                </div>
                <p><strong>File:</strong> <code>{html.escape(f.file)}</code> (Line {f.line or 'N/A'})</p>
                <p><strong>Scanner:</strong> {html.escape(f.scanner)} | <strong>CWE:</strong> {html.escape(f.cwe or 'N/A')} | <strong>OWASP:</strong> {html.escape(f.owasp or 'N/A')}</p>
                <p><strong>Description:</strong> {html.escape(f.description or 'No detailed description available.')}</p>
                <div style="background: #0f172a; color: #e2e8f0; padding: 0.75rem; border-radius: 6px; font-family: monospace; margin-top: 0.5rem;">
                    <strong>AI Recommendation:</strong> {html.escape(recommendation)}
                </div>
            </div>
            """

        date_str = scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.started_at else "N/A"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureGuard Security Audit Report - {html.escape(scan.id)}</title>
    <style>
        :root {{
            --primary: #0284c7;
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-medium: #eab308;
            --sev-low: #3b82f6;
        }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 2rem;
            color: #1e293b;
            background-color: #f8fafc;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .brand {{
            font-size: 1.75rem;
            font-weight: 700;
            color: #0f172a;
        }}
        .brand span {{ color: var(--primary); }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: white;
            padding: 1.25rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .metric-title {{ font-size: 0.875rem; color: #64748b; margin-bottom: 0.5rem; }}
        .metric-value {{ font-size: 1.5rem; font-weight: 700; color: #0f172a; }}
        .badge {{
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            color: white;
        }}
        .badge-critical {{ background: var(--sev-critical); }}
        .badge-high {{ background: var(--sev-high); }}
        .badge-medium {{ background: var(--sev-medium); }}
        .badge-low {{ background: var(--sev-low); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }}
        th, td {{
            padding: 0.875rem 1rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 0.875rem;
        }}
        th {{ background: #f1f5f9; font-weight: 600; color: #475569; }}
        h2 {{ color: #0f172a; margin-top: 2rem; margin-bottom: 1rem; }}
        .footer {{
            text-align: center;
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid #e2e8f0;
            font-size: 0.875rem;
            color: #94a3b8;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="brand"><span>SecureGuard</span> Enterprise Security Report</div>
        <div>Scan ID: <code>{html.escape(scan.id[:8])}</code></div>
    </div>

    <div class="meta-grid">
        <div class="card">
            <div class="metric-title">Target Repository</div>
            <div class="metric-value">{html.escape(repo_name)}</div>
        </div>
        <div class="card">
            <div class="metric-title">Commit SHA</div>
            <div class="metric-value"><code>{html.escape(scan.commit_sha[:7])}</code></div>
        </div>
        <div class="card">
            <div class="metric-title">Risk Score</div>
            <div class="metric-value">{risk_score}/100 ({risk_level})</div>
        </div>
        <div class="card">
            <div class="metric-title">Scan Timestamp</div>
            <div class="metric-value" style="font-size: 1rem;">{date_str}</div>
        </div>
    </div>

    <h2>Executive Summary</h2>
    <div class="card" style="margin-bottom: 2rem;">
        <p>A comprehensive automated security scan was conducted for <strong>{html.escape(repo_name)}</strong> on branch <code>{html.escape(scan.branch)}</code>. The scan analyzed source code and commit history using secret scanners (Gitleaks) and SAST engines (Semgrep).</p>
        <div style="display: flex; gap: 2rem; margin-top: 1rem;">
            <div><strong>Total Findings:</strong> {len(findings)}</div>
            <div><strong>Critical:</strong> <span style="color: var(--sev-critical); font-weight: bold;">{crit_count}</span></div>
            <div><strong>High:</strong> <span style="color: var(--sev-high); font-weight: bold;">{high_count}</span></div>
            <div><strong>Medium:</strong> <span style="color: var(--sev-medium); font-weight: bold;">{med_count}</span></div>
            <div><strong>Low:</strong> <span style="color: var(--sev-low); font-weight: bold;">{low_count}</span></div>
        </div>
    </div>

    <h2>Security Findings Overview</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Vulnerability Title</th>
                <th>Location</th>
                <th>Scanner</th>
                <th>CWE</th>
                <th>OWASP</th>
            </tr>
        </thead>
        <tbody>
            {findings_rows}
        </tbody>
    </table>

    <h2>Top Priority Remediation Advice</h2>
    {top_findings_detail}

    <h2>Compliance & Standards Mapping</h2>
    <div class="card">
        <p><strong>OWASP Top 10 Coverage:</strong> A01:2021-Broken Access Control, A03:2021-Injection, A07:2021-Identification and Authentication Failures.</p>
        <p><strong>MITRE ATT&CK Mapping:</strong> T1552 - Unsecured Credentials, T1190 - Exploit Public-Facing Application.</p>
    </div>

    <div class="footer">
        Generated by SecureGuard Automated DevSecOps Platform &bull; Confidential
    </div>
</body>
</html>"""

    def generate_pdf_report(self, scan: ScanModel) -> bytes:
        """Generate PDF report bytes from scan results (or fallback to HTML bytes)."""
        html_content = self.generate_html_report(scan)
        try:
            import weasyprint
            return weasyprint.HTML(string=html_content).write_pdf()
        except Exception as e:
            logger.warning("WeasyPrint PDF conversion unavailable, returning HTML bytes fallback: %s", str(e))
            return html_content.encode("utf-8")
