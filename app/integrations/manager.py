"""
Purpose: SOC Integration Manager wrapper for backward compatibility.
"""

from app.integrations.connector_manager import SOCIntegrationManager, ConnectorManager

__all__ = ["SOCIntegrationManager", "ConnectorManager"]
