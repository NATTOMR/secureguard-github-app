"""
Purpose: Abstract Base Class for SecureGuard Connectors and SOC Integrations.

Responsibilities:
- Define BaseConnector contract methods for SIEM, SOAR, Threat Intel, and Alert connectors.
- Provide backward-compatible SOCProvider interface.

Dependencies:
- abc.ABC, abstractmethod
- typing.Dict, Any, List, Optional
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseConnector(ABC):
    """Abstract Base Class for all SecureGuard integration connectors."""

    @property
    @abstractmethod
    def connector_name(self) -> str:
        """Canonical connector platform name identifier."""
        pass

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection or verify configuration credentials."""
        pass

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check API connectivity and health status."""
        pass

    @abstractmethod
    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Forward scan summary metadata to destination platform."""
        pass

    @abstractmethod
    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Forward list of security findings to destination platform."""
        pass

    @abstractmethod
    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch security finding alert."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Safely close underlying HTTP client or connection resources."""
        pass


class SOCProvider(BaseConnector):
    """Backward-compatible SOCProvider abstract class."""

    @property
    def connector_name(self) -> str:
        return self.platform_name

    @property
    @abstractmethod
    def platform_name(self) -> str:
        pass

    async def connect(self) -> bool:
        res = await self.health()
        return res.get("status") in ("ok", "healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        return await self.health()

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(scan_data)

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"findings": findings})

    async def close(self) -> None:
        pass

    @abstractmethod
    async def health(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def send_incident(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def send_ioc(self, ioc_payload: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def close_alert(self, alert_id: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def search(self, query: str) -> Dict[str, Any]:
        pass
