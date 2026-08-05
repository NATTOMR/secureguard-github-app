"""
Purpose: REST API router for SOC Platform Integrations.

Responsibilities:
- Provide /api/integrations/status, /wazuh, /splunk, /elastic, /sentinel, /thehive, /misp.

Dependencies:
- fastapi.APIRouter, status
- app.integrations.manager.SOCIntegrationManager
- app.schemas.integrations.DispatchAlertRequest

Usage:
    Included in main API router.
"""

from typing import Any, Dict
from fastapi import APIRouter, status
from app.integrations.manager import SOCIntegrationManager
from app.schemas.integrations import DispatchAlertRequest

router = APIRouter(prefix="/api/integrations", tags=["SOC Integrations"])


@router.get(
    "/status",
    status_code=status.HTTP_200_OK,
    summary="SOC Integrations Health Status",
    description="Returns connectivity and configuration status for all 6 SOC integration platforms.",
)
async def get_integrations_status() -> Dict[str, Any]:
    """Get status across Wazuh, Splunk, Elastic, Sentinel, TheHive, and MISP."""
    manager = SOCIntegrationManager()
    return await manager.get_all_health()


@router.post(
    "/dispatch",
    status_code=status.HTTP_200_OK,
    summary="Dispatch Alert to all SOC Platforms",
)
async def dispatch_alert_to_all(req: DispatchAlertRequest) -> Dict[str, Any]:
    """Dispatch normalized security finding alert to all active SOC platforms."""
    manager = SOCIntegrationManager()
    return await manager.dispatch_alert(req.model_dump())


@router.get(
    "/wazuh",
    status_code=status.HTTP_200_OK,
    summary="Wazuh Integration Status",
)
async def get_wazuh_status() -> Dict[str, Any]:
    """Get Wazuh health status."""
    manager = SOCIntegrationManager()
    return await manager.providers["wazuh"].health()


@router.get(
    "/splunk",
    status_code=status.HTTP_200_OK,
    summary="Splunk HEC Integration Status",
)
async def get_splunk_status() -> Dict[str, Any]:
    """Get Splunk health status."""
    manager = SOCIntegrationManager()
    return await manager.providers["splunk"].health()


@router.get(
    "/elastic",
    status_code=status.HTTP_200_OK,
    summary="Elastic Security ECS Status",
)
async def get_elastic_status() -> Dict[str, Any]:
    """Get Elastic Security health status."""
    manager = SOCIntegrationManager()
    return await manager.providers["elastic"].health()


@router.get(
    "/sentinel",
    status_code=status.HTTP_200_OK,
    summary="Microsoft Sentinel Status",
)
async def get_sentinel_status() -> Dict[str, Any]:
    """Get Microsoft Sentinel health status."""
    manager = SOCIntegrationManager()
    return await manager.providers["sentinel"].health()


@router.get(
    "/thehive",
    status_code=status.HTTP_200_OK,
    summary="TheHive SOAR Status",
)
async def get_thehive_status() -> Dict[str, Any]:
    """Get TheHive health status."""
    manager = SOCIntegrationManager()
    return await manager.providers["thehive"].health()


@router.get(
    "/misp",
    status_code=status.HTTP_200_OK,
    summary="MISP Threat Intel Status",
)
async def get_misp_status() -> Dict[str, Any]:
    """Get MISP health status."""
    manager = SOCIntegrationManager()
    return await manager.providers["misp"].health()
