"""
Purpose: Static Application Security Testing (SAST) engine using Semgrep.

Responsibilities:
- Attempt to run Semgrep CLI against target code directory for maximum accuracy.
- Fall back to high-performance native Python SAST engine (sast_rules.py) if Semgrep is not available.
- Parse findings into SecureGuard standard format.

Dependencies:
- app.scanners.base.BaseScanner
- app.scanners.sast_rules.run_sast_scan
- app.core.logging.get_logger
- pathlib.Path
- asyncio, subprocess, json, shutil

Usage:
    scanner = SemgrepScanner()
    results = await scanner.scan(repo_path)
"""

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List

from app.core.logging import get_logger
from app.scanners.base import BaseScanner
from app.scanners.sast_rules import run_sast_scan

logger = get_logger(__name__)

# File extensions that the native SAST engine supports
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}


class SemgrepScanner(BaseScanner):
    """Semgrep SAST security scanner — uses Semgrep CLI if available, native engine otherwise."""

    @property
    def name(self) -> str:
        return "Semgrep"

    def _semgrep_available(self) -> bool:
        """Check whether Semgrep CLI is installed and available on system PATH."""
        return shutil.which("semgrep") is not None

    async def _run_semgrep_cli(self, target_dir: Path) -> List[Dict[str, Any]]:
        """Run Semgrep CLI with OWASP ruleset and parse JSON output."""
        cmd = [
            "semgrep",
            "--config", "p/owasp-top-ten",
            "--config", "p/python",
            "--config", "p/javascript",
            "--json",
            "--quiet",
            str(target_dir),
        ]
        logger.info("Running Semgrep CLI on %s", target_dir)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        except asyncio.TimeoutError:
            logger.warning("Semgrep CLI timed out. Falling back to native SAST engine.")
            return await self._run_native_engine(target_dir)
        except Exception as e:
            logger.warning("Semgrep CLI execution failed (%s). Falling back to native SAST engine.", str(e))
            return await self._run_native_engine(target_dir)

        try:
            data = json.loads(stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            logger.warning("Failed to parse Semgrep JSON output. Falling back to native SAST engine.")
            return await self._run_native_engine(target_dir)

        findings: List[Dict[str, Any]] = []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            severity_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "INFO",
            }
            severity = severity_map.get(extra.get("severity", "INFO"), "INFO")
            findings.append({
                "rule_id": result.get("check_id", "semgrep-unknown"),
                "title": extra.get("message", "Semgrep Finding"),
                "severity": severity,
                "file_path": str(Path(result.get("path", "")).relative_to(target_dir)).replace("\\", "/"),
                "line_number": result.get("start", {}).get("line"),
                "description": extra.get("message", ""),
                "recommendation": "Review Semgrep rule documentation for secure coding guidance.",
                "scanner_name": "Semgrep",
            })
        logger.info("Semgrep CLI found %d issues in %s", len(findings), target_dir)
        return findings

    async def _run_native_engine(self, target_dir: Path) -> List[Dict[str, Any]]:
        """Run native Python SAST engine as a fallback across supported file types."""
        logger.info("Running native SAST engine on %s", target_dir)
        findings: List[Dict[str, Any]] = []
        import os
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "__pycache__", ".venv", "venv")]
            for file_name in files:
                file_path = Path(root) / file_name
                if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                    continue
                try:
                    content = file_path.read_text(encoding="utf-8")
                    rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")
                    file_findings = run_sast_scan(content, rel_path)
                    findings.extend(file_findings)
                except UnicodeDecodeError:
                    continue
                except Exception:
                    continue
        logger.info("Native SAST engine found %d issues in %s", len(findings), target_dir)
        return findings

    async def scan(self, target_dir: Path) -> List[Dict[str, Any]]:
        """Run SAST scan — prefer Semgrep CLI, fall back to native Python engine."""
        if self._semgrep_available():
            logger.info("Semgrep CLI detected. Using Semgrep for SAST analysis.")
            return await self._run_semgrep_cli(target_dir)
        logger.info("Semgrep CLI not found. Using native SAST engine.")
        return await self._run_native_engine(target_dir)

