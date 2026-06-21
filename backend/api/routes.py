"""
REST API Routes — v1 endpoints for traffic data, alerts, and stats.
"""
from fastapi import APIRouter, Query
from typing import Optional

router = APIRouter(tags=["API v1"])


@router.get("/traffic")
async def get_traffic(limit: int = Query(100, le=1000)):
    """Retrieve recent traffic logs."""
    from main import alert_manager
    data = alert_manager.get_recent_traffic(limit=limit)
    return {"count": len(data), "data": data}


@router.get("/alerts")
async def get_alerts(
    limit: int = Query(50, le=500),
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
):
    """Retrieve recent alerts with optional filters."""
    from main import alert_manager
    alerts = alert_manager.get_recent_alerts(limit=limit)
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    if attack_type:
        alerts = [a for a in alerts if a.get("attack_type") == attack_type]
    return {"count": len(alerts), "data": alerts}


@router.get("/stats")
async def get_stats():
    """Retrieve current traffic statistics and analytics."""
    from main import alert_manager
    return alert_manager.get_stats()


@router.get("/top-ips")
async def get_top_ips(limit: int = Query(10, le=50)):
    """Get top IPs by traffic volume."""
    from main import alert_manager
    stats = alert_manager.get_stats()
    return {"data": stats["top_ips"][:limit]}


@router.get("/attack-summary")
async def get_attack_summary():
    """Get attack type distribution."""
    from main import alert_manager
    stats = alert_manager.get_stats()
    return {
        "attack_distribution": stats["attack_distribution"],
        "total_alerts": stats["total_alerts"],
    }
