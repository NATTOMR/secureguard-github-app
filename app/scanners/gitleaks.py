"""
Purpose: Secret detection engine using Gitleaks (Phase 3).

Responsibilities:
- Run secret detection against target code directory.
- Parse JSON scan output into structured findings.
- Use native Python regex fallback if Gitleaks CLI is unavailable.

Dependencies:
- app.scanners.base.BaseScanner
- app.scanners.secret_rules.detect_secrets
- pathlib.Path
- os

Usage:
    scanner = GitleaksScanner()
    results = await scanner.scan(repo_path)
"""

import os
from pathlib import Path
from typing import Any, Dict, List
from app.scanners.base import BaseScanner
from app.scanners.secret_rules import detect_secrets


class GitleaksScanner(BaseScanner):
    """Gitleaks secret detection scanner implementation."""

    @property
    def name(self) -> str:
        return "Gitleaks (Native Fallback)"

    async def scan(self, target_dir: Path) -> List[Dict[str, Any]]:
        """Run secret detection scan on target directory."""
        findings = []
        
        # Traverse the directory and scan files using the native fallback engine
        for root, dirs, files in os.walk(target_dir):
            # Skip hidden directories like .git
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file_name in files:
                # Skip known binary or heavy files if necessary, for now scan all
                file_path = Path(root) / file_name
                try:
                    # Attempt to read as utf-8
                    content = file_path.read_text(encoding='utf-8')
                    # Compute relative path for reporting
                    rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")
                    file_findings = detect_secrets(content, rel_path)
                    findings.extend(file_findings)
                except UnicodeDecodeError:
                    # Skip binary files that cannot be read as text
                    continue
                except Exception:
                    # Skip files with other read errors (permissions, etc.)
                    continue
                    
        return findings
