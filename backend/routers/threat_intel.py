from typing import Dict, Any
from fastapi import APIRouter, Query
from backend.services.threat_intel import threat_intel_service, KNOWN_IOC_DATABASE

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])


@router.get("/lookup")
def lookup_ip_threat_intel(ip: str = Query(..., description="IP address or host indicator to inspect")):
    """Queries Threat Intelligence reputation, threat score, and categories for a target IP address."""
    return threat_intel_service.lookup_ip(ip)


@router.get("/database")
def get_known_ioc_database():
    """Returns local high-fidelity Threat Intelligence indicator repository."""
    return {
        "total_indicators": len(KNOWN_IOC_DATABASE),
        "indicators": KNOWN_IOC_DATABASE
    }
