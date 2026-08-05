"""
Purpose: REST API router for Enterprise SOC Platform & Notification Integrations.

Responsibilities:
- Provide `GET /api/integrations`, `/status`, `/events`, `POST /test`, `/enable`, `/disable`.
- Provide platform-specific endpoints for Wazuh, Splunk, Sentinel, Elastic, TheHive, MISP, Slack, Teams, Discord.

Dependencies:
- fastapi.APIRouter, Depends, HTTPException, status, Body
- sqlalchemy.orm.Session
- app.db.session.get_db
- app.db.repository.DatabaseRepository
- app.integrations.connector_manager.ConnectorManager
- app.schemas.integrations.DispatchAlertRequest

Usage:
    Included in main API router.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body
from sqlalchemy.orm import Session

from app.db.repository import DatabaseRepository
from app.db.session import get_db
from app.integrations.connector_manager import ConnectorManager
from app.schemas.integrations import DispatchAlertRequest

router = APIRouter(prefix="/api/integrations", tags=["SOC Integrations"])
_manager = ConnectorManager()


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List Registered SOC Connectors",
)
async def list_integrations() -> Dict[str, Any]:
    """List all registered connectors and their status."""
    return await _manager.get_all_status()


@router.get(
    "/status",
    status_code=status.HTTP_200_OK,
    summary="SOC Integrations Health Status",
)
async def get_integrations_status() -> Dict[str, Any]:
    """Get status across all registered connectors."""
    return await _manager.get_all_status()


@router.get(
    "/events",
    status_code=status.HTTP_200_OK,
    summary="List Outbound Integration Audit Events",
)
def list_integration_events(
    connector: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """List recorded outbound integration events."""
    dao = DatabaseRepository(db)
    events = dao.get_integration_events(connector=connector, limit=limit)
    return [
        {
            "id": e.id,
            "connector": e.connector,
            "status": e.status,
            "repository": e.repository,
            "scan_id": e.scan_id,
            "response": e.response,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in events
    ]


@router.post(
    "/test",
    status_code=status.HTTP_200_OK,
    summary="Test Integration Connector Connectivity",
)
async def test_connector(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Test connector connectivity."""
    connector_name = payload.get("connector", "wazuh").lower()
    connector = _manager.get_connector(connector_name)
    if not connector:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Connector {connector_name} not found")
    
    health = await connector.health_check()
    return {"connector": connector_name, "health": health}


@router.post(
    "/enable",
    status_code=status.HTTP_200_OK,
    summary="Enable Integration Connector",
)
def enable_connector(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Enable connector at runtime."""
    connector_name = payload.get("connector", "").lower()
    success = _manager.enable_connector(connector_name)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Connector {connector_name} not found")
    return {"connector": connector_name, "enabled": True}


@router.post(
    "/disable",
    status_code=status.HTTP_200_OK,
    summary="Disable Integration Connector",
)
def disable_connector(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Disable connector at runtime."""
    connector_name = payload.get("connector", "").lower()
    success = _manager.disable_connector(connector_name)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Connector {connector_name} not found")
    return {"connector": connector_name, "enabled": False}


@router.post(
    "/dispatch",
    status_code=status.HTTP_200_OK,
    summary="Dispatch Alert to all Enabled SOC Connectors",
)
async def dispatch_alert_to_all(req: DispatchAlertRequest) -> Dict[str, Any]:
    """Dispatch normalized security finding alert to all active SOC connectors."""
    from app.integrations.connector_manager import SOCIntegrationManager
    soc_mgr = SOCIntegrationManager()
    return await soc_mgr.dispatch_alert(req.model_dump())


# ------------------------------------------------------------------
# Platform-Specific Endpoints
# ------------------------------------------------------------------

@router.post("/wazuh/send", status_code=status.HTTP_200_OK)
async def wazuh_send(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("wazuh")
    return await conn.send_alert(payload)

@router.get("/wazuh/status", status_code=status.HTTP_200_OK)
@router.get("/wazuh/health", status_code=status.HTTP_200_OK)
@router.get("/wazuh", status_code=status.HTTP_200_OK)
async def wazuh_status() -> Dict[str, Any]:
    conn = _manager.get_connector("wazuh")
    return await conn.health_check()


@router.post("/splunk/send", status_code=status.HTTP_200_OK)
async def splunk_send(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("splunk")
    return await conn.send_alert(payload)

@router.get("/splunk/status", status_code=status.HTTP_200_OK)
@router.get("/splunk", status_code=status.HTTP_200_OK)
async def splunk_status() -> Dict[str, Any]:
    conn = _manager.get_connector("splunk")
    return await conn.health_check()


@router.post("/sentinel/send", status_code=status.HTTP_200_OK)
async def sentinel_send(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("sentinel")
    return await conn.send_alert(payload)

@router.get("/sentinel/status", status_code=status.HTTP_200_OK)
@router.get("/sentinel", status_code=status.HTTP_200_OK)
async def sentinel_status() -> Dict[str, Any]:
    conn = _manager.get_connector("sentinel")
    return await conn.health_check()


@router.post("/elastic/send", status_code=status.HTTP_200_OK)
async def elastic_send(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("elastic")
    return await conn.send_alert(payload)

@router.get("/elastic/status", status_code=status.HTTP_200_OK)
@router.get("/elastic", status_code=status.HTTP_200_OK)
async def elastic_status() -> Dict[str, Any]:
    conn = _manager.get_connector("elastic")
    return await conn.health_check()


@router.post("/thehive/alert", status_code=status.HTTP_200_OK)
@router.post("/thehive/case", status_code=status.HTTP_200_OK)
async def thehive_send(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("thehive")
    return await conn.send_alert(payload)

@router.get("/thehive/status", status_code=status.HTTP_200_OK)
@router.get("/thehive", status_code=status.HTTP_200_OK)
async def thehive_status() -> Dict[str, Any]:
    conn = _manager.get_connector("thehive")
    return await conn.health_check()


@router.post("/misp/event", status_code=status.HTTP_200_OK)
async def misp_send(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("misp")
    return await conn.send_alert(payload)

@router.get("/misp/status", status_code=status.HTTP_200_OK)
@router.get("/misp", status_code=status.HTTP_200_OK)
async def misp_status() -> Dict[str, Any]:
    conn = _manager.get_connector("misp")
    return await conn.health_check()


@router.post("/slack/test", status_code=status.HTTP_200_OK)
async def slack_test(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("slack")
    return await conn.send_alert(payload)


@router.post("/teams/test", status_code=status.HTTP_200_OK)
async def teams_test(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("teams")
    return await conn.send_alert(payload)


@router.post("/discord/test", status_code=status.HTTP_200_OK)
async def discord_test(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    conn = _manager.get_connector("discord")
    return await conn.send_alert(payload)
