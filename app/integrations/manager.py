"""
Purpose: SOC Integration Manager for orchestrating security alert dispatching.

Responsibilities:
- Manage registration of Wazuh, Splunk, Elastic, Sentinel, TheHive, and MISP providers.
- Normalize incoming findings into canonical security alert events.
- Broadcast alert payloads to all configured active SOC platforms.

Dependencies:
- typing.Dict, List, Any
- app.integrations.base.SOCProvider
- app.integrations.wazuh.client.WazuhProvider
- app.integrations.splunk.client.SplunkProvider
- app.integrations.elastic.client.ElasticProvider
- app.integrations.sentinel.client.SentinelProvider
- app.integrations.thehive.client.TheHiveProvider
- app.integrations.misp.client.MISPProvider

Usage:
    manager = SOCIntegrationManager()
    results = await manager.dispatch_alert(finding_data)
"""

from typing import Any, Dict, List
from app.integrations.base import SOCProvider
from app.integrations.elastic.client import ElasticProvider
from app.integrations.misp.client import MISPProvider
from app.integrations.sentinel.client import SentinelProvider
from app.integrations.splunk.client import SplunkProvider
from app.integrations.thehive.client import TheHiveProvider
from app.integrations.wazuh.client import WazuhProvider


class SOCIntegrationManager:
    """Orchestrator for enterprise SOC platform integrations."""

    def __init__(self) -> None:
        self.providers: Dict[str, SOCProvider] = {
            "wazuh": WazuhProvider(),
            "splunk": SplunkProvider(),
            "elastic": ElasticProvider(),
            "sentinel": SentinelProvider(),
            "thehive": TheHiveProvider(),
            "misp": MISPProvider(),
        }

    async def get_all_health(self) -> Dict[str, Any]:
        """Check health status across all registered SOC platforms."""
        statuses = {}
        for name, provider in self.providers.items():
            statuses[name] = await provider.health()
        return statuses

    async def dispatch_alert(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize finding and broadcast to all active SOC providers."""
        normalized_event = {
            "timestamp": finding.get("timestamp"),
            "repository": finding.get("repository", "unknown/repo"),
            "commit": finding.get("commit_sha", "7fd1a60"),
            "author": finding.get("author", "NATTOMR"),
            "scanner": finding.get("scanner", "Gitleaks"),
            "severity": finding.get("severity", "HIGH"),
            "rule": finding.get("rule_id", "security-finding"),
            "cvss": finding.get("cvss", 8.5),
            "cwe": finding.get("cwe", "CWE-798"),
            "owasp": finding.get("owasp", "A07:2021"),
            "mitre_attack": finding.get("mitre_attack", "T1552.001"),
            "ai_summary": finding.get("ai_summary", "Security risk detected."),
            "recommendation": finding.get("recommendation", "Remediate finding."),
        }

        dispatch_results = {}
        for name, provider in self.providers.items():
            try:
                dispatch_results[name] = await provider.send_alert(normalized_event)
            except Exception as e:
                dispatch_results[name] = {"status": "failed", "error": str(e)}

        return {
            "event": normalized_event,
            "dispatches": dispatch_results,
        }
