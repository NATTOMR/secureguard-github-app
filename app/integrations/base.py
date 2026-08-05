"""
Purpose: Abstract Base Class for SecureGuard SOC Integrations.

Responsibilities:
- Define contract methods for SIEM, SOAR, and Threat Intelligence integrations.

Dependencies:
- abc.ABC, abstractmethod
- typing.Dict, Any, Optional

Usage:
    class WazuhProvider(SOCProvider):
        ...
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class SOCProvider(ABC):
    """Abstract Base Class for enterprise SOC integrations."""

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Canonical platform name identifier."""
        pass

    @abstractmethod
    async def health(self) -> Dict[str, Any]:
        """Check API connectivity and integration health status."""
        pass

    @abstractmethod
    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch security finding alert."""
        pass

    @abstractmethod
    async def send_incident(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create SOAR incident/case."""
        pass

    @abstractmethod
    async def send_ioc(self, ioc_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Push threat intelligence IOC attributes."""
        pass

    @abstractmethod
    async def close_alert(self, alert_id: str) -> Dict[str, Any]:
        """Close/resolve security alert."""
        pass

    @abstractmethod
    async def search(self, query: str) -> Dict[str, Any]:
        """Search platform for historical security events."""
        pass
