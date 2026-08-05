"""
Purpose: Generate SARIF 2.1.0 compliant JSON reports from security scan findings.

Responsibilities:
- Convert ScanModel and associated FindingModel records into valid SARIF 2.1.0 output.
- Map SecureGuard severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO) to SARIF levels.
- Deduplicate rule entries and build a stable rule-index mapping.
- Generate deterministic fingerprints for finding deduplication across runs.
- Include CWE and OWASP identifiers in rule properties when available.

Dependencies:
- hashlib
- datetime
- app.db.models.ScanModel, FindingModel
- app.core.logging.get_logger

Usage:
    from app.services.sarif_service import SARIFService

    service = SARIFService()
    sarif_json = service.generate_sarif(scan)
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from app.core.logging import get_logger
from app.db.models import FindingModel, ScanModel

logger = get_logger(__name__)

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "SecureGuard"
_TOOL_VERSION = "0.1.0"
_TOOL_INFO_URI = "https://github.com/NATTOMR/secureguard-github-app"

_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


class SARIFService:
    """Generates SARIF 2.1.0 compliant JSON from SecureGuard scan data."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_sarif(self, scan: ScanModel) -> Dict[str, Any]:
        """Build a complete SARIF 2.1.0 document for the given scan.

        Args:
            scan: A fully-loaded ScanModel instance whose ``findings``
                  relationship has been eagerly loaded.

        Returns:
            A dictionary representing the SARIF JSON document ready for
            serialisation via ``json.dumps``.
        """
        findings: List[FindingModel] = list(scan.findings)
        logger.info(
            "Generating SARIF report for scan %s with %d findings",
            scan.id,
            len(findings),
        )

        rules, rule_index_map = self._build_rules(findings)
        results = self._build_results(findings, rule_index_map)
        invocation = self._build_invocation(scan)

        sarif: Dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": _TOOL_INFO_URI,
                            "rules": rules,
                        },
                    },
                    "results": results,
                    "invocations": [invocation],
                },
            ],
        }

        logger.info(
            "SARIF report generated: %d rules, %d results",
            len(rules),
            len(results),
        )
        return sarif

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _map_severity_to_level(self, severity: str) -> str:
        """Map a SecureGuard severity string to a SARIF result level.

        Unrecognised severity values default to ``"note"``.
        """
        return _SEVERITY_TO_LEVEL.get(severity.upper(), "note")

    def _build_rules(
        self, findings: List[FindingModel]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """Extract unique SARIF rule descriptors from a list of findings.

        Returns:
            A tuple of ``(rules_list, rule_index_map)`` where
            *rule_index_map* maps each ``rule_id`` to its positional index
            inside *rules_list*.
        """
        rules: List[Dict[str, Any]] = []
        rule_index_map: Dict[str, int] = {}

        for finding in findings:
            rule_id = finding.rule
            if rule_id in rule_index_map:
                continue

            rule_entry: Dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {
                    "text": finding.title,
                },
                "defaultConfiguration": {
                    "level": self._map_severity_to_level(finding.severity),
                },
            }

            # Full description from the finding (optional field)
            if finding.description:
                rule_entry["fullDescription"] = {"text": finding.description}

            # Help / recommendation text
            if finding.recommendation:
                rule_entry["help"] = {
                    "text": finding.recommendation,
                    "markdown": finding.recommendation,
                }

            # Rule properties – CWE, OWASP, scanner tags
            properties: Dict[str, Any] = {}
            tags: List[str] = []

            if finding.cwe:
                properties["cwe"] = finding.cwe
                tags.append(f"external/cwe/{finding.cwe}")

            if finding.owasp:
                properties["owasp"] = finding.owasp
                tags.append(f"external/owasp/{finding.owasp}")

            if finding.category:
                tags.append(finding.category)

            if finding.scanner:
                properties["scanner"] = finding.scanner

            if tags:
                properties["tags"] = tags

            if properties:
                rule_entry["properties"] = properties

            rule_index_map[rule_id] = len(rules)
            rules.append(rule_entry)

        return rules, rule_index_map

    def _build_results(
        self,
        findings: List[FindingModel],
        rule_index_map: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        """Convert each finding into a SARIF result object.

        Args:
            findings: All findings associated with the scan.
            rule_index_map: Mapping of rule id → index produced by
                :meth:`_build_rules`.

        Returns:
            A list of SARIF result dictionaries.
        """
        results: List[Dict[str, Any]] = []

        for finding in findings:
            result_entry: Dict[str, Any] = {
                "ruleId": finding.rule,
                "ruleIndex": rule_index_map.get(finding.rule, 0),
                "level": self._map_severity_to_level(finding.severity),
                "message": {
                    "text": finding.title,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": self._build_region(finding),
                        },
                    },
                ],
                "fingerprints": {
                    "secureguard/v1": self._generate_fingerprint(finding),
                },
            }

            # Attach supplementary properties when present
            properties: Dict[str, Any] = {}
            if finding.severity:
                properties["severity"] = finding.severity
            if finding.confidence:
                properties["confidence"] = finding.confidence
            if finding.cvss is not None:
                properties["cvss"] = finding.cvss
            if finding.scanner:
                properties["scanner"] = finding.scanner
            if finding.category:
                properties["category"] = finding.category
            if finding.mitre:
                properties["mitre"] = finding.mitre
            if finding.status:
                properties["status"] = finding.status

            if properties:
                result_entry["properties"] = properties

            results.append(result_entry)

        return results

    def _generate_fingerprint(self, finding: FindingModel) -> str:
        """Produce a deterministic SHA-256 fingerprint for deduplication.

        The fingerprint is derived from the combination of the finding's
        rule id, file path, and line number so that identical findings
        across successive scans can be correlated.
        """
        line_str = str(finding.line) if finding.line is not None else "0"
        raw = f"{finding.rule}:{finding.file}:{line_str}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Private utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _build_region(finding: FindingModel) -> Dict[str, Any]:
        """Construct a SARIF ``region`` object from a finding's line info."""
        region: Dict[str, Any] = {}
        if finding.line is not None:
            region["startLine"] = finding.line
        return region

    @staticmethod
    def _build_invocation(scan: ScanModel) -> Dict[str, Any]:
        """Construct a SARIF ``invocation`` object from scan metadata."""
        execution_successful = scan.status == "completed"

        invocation: Dict[str, Any] = {
            "executionSuccessful": execution_successful,
        }

        if scan.started_at:
            invocation["startTimeUtc"] = scan.started_at.astimezone(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

        if scan.finished_at:
            invocation["endTimeUtc"] = scan.finished_at.astimezone(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

        properties: Dict[str, Any] = {
            "scanId": scan.id,
            "trigger": scan.trigger,
            "branch": scan.branch,
            "commitSha": scan.commit_sha,
        }

        if scan.duration is not None:
            properties["durationSeconds"] = scan.duration

        if scan.scanner_versions:
            properties["scannerVersions"] = scan.scanner_versions

        invocation["properties"] = properties
        return invocation
