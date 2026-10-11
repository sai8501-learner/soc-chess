import json
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.services.llm_analyst import llm_analyst
from backend.services.llm_gateway import llm_gateway
from backend.database import query

router = APIRouter(prefix="/api/llm", tags=["NVIDIA NIM LLM SOC Analyst Gateway"])


class InvestigateAlertRequest(BaseModel):
    id: Optional[int] = None
    attack_type: str = Field(default="DDoS")
    prediction: Optional[str] = None
    confidence: Optional[float] = 96.4
    mlp_confidence: Optional[float] = 96.4
    risk_score: Optional[float] = 88.0
    risk_status: Optional[str] = "CRITICAL"
    severity: Optional[str] = "CRITICAL"
    source_ip: Optional[str] = "192.168.56.104"
    destination_ip: Optional[str] = "192.168.56.107"
    source_port: Optional[int] = 54321
    destination_port: Optional[int] = 80
    protocol: Optional[str] = "TCP"
    threat_intel: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    raw_event: Optional[Dict[str, Any]] = None


class AnalyzeIocRequest(BaseModel):
    ioc: str = Field(..., description="IOC string (IP, Domain, URL, Hash, CVE, etc.)")
    ioc_type: Optional[str] = Field(default="Auto Detect")
    threat_score: Optional[float] = 0.0
    reputation: Optional[str] = "UNKNOWN"
    source: Optional[str] = "Local IOC Database"
    observation_count: Optional[int] = 1
    related_alerts: Optional[List[Dict[str, Any]]] = Field(default_factory=list)


class InvestigateIncidentRequest(BaseModel):
    incident_id: str
    title: Optional[str] = None
    attack_type: str = "DDoS"
    severity: Optional[str] = "HIGH"
    priority: Optional[str] = "P2"
    status: Optional[str] = "NEW"
    risk_score: Optional[float] = 75.0
    risk_status: Optional[str] = "HIGH"
    mlp_confidence: Optional[float] = 95.0
    source_ip: Optional[str] = "192.168.56.104"
    destination_ip: Optional[str] = "192.168.56.107"
    source_port: Optional[int] = 0
    destination_port: Optional[int] = 80
    protocol: Optional[str] = "TCP"
    threat_intel: Optional[Dict[str, Any]] = Field(default_factory=dict)
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict)
    splunk_evidence: Optional[List[Dict[str, Any]]] = Field(default_factory=list)


class SummarizeCaseRequest(BaseModel):
    case_id: str
    title: str = "SOC Investigation Case"
    priority: Optional[str] = "MEDIUM"
    status: Optional[str] = "OPEN"
    assigned_analyst: Optional[str] = "Lead Analyst"
    related_incidents: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    related_alerts: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    notes: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    evidence_summary: Optional[Dict[str, Any]] = Field(default_factory=dict)


@router.get("/status")
def get_llm_status():
    """Returns the live status, configured models, and failover order of NVIDIA NIM LLM Gateway."""
    return llm_gateway.get_status()


@router.get("/models")
def get_llm_models():
    """Lists supported NVIDIA and fallback LLM models."""
    return {
        "primary": {
            "name": "NVIDIA Nemotron 3.5 Lightning (30B)",
            "id": llm_gateway.primary_model,
            "role": "PRIMARY_INVESTIGATION_ENGINE"
        },
        "secondary": {
            "name": "DeepSeek V4 Pro",
            "id": llm_gateway.secondary_model,
            "role": "SECONDARY_FAILOVER_ENGINE"
        },
        "tertiary": {
            "name": "Moonshot Kimi K3",
            "id": llm_gateway.tertiary_model,
            "role": "TERTIARY_FAILOVER_ENGINE"
        },
        "offline_fallback": {
            "name": "Deterministic SOC Expert System",
            "id": "soc-rules-expert-v2",
            "role": "ZERO_FAIL_OFFLINE_ENGINE"
        }
    }


@router.get("/history")
def get_llm_history(limit: int = Query(50, ge=1, le=200)):
    """Retrieves audit trail of past AI investigations and reports."""
    try:
        rows = query("""
            SELECT id, analysis_type, reference_id, provider, model, status, duration_ms, created_at,
                   output_response
            FROM llm_analysis_history
            ORDER BY id DESC
            LIMIT %s;
        """, (limit,))
        for r in rows:
            if isinstance(r.get("output_response"), str):
                try:
                    r["output_response"] = json.loads(r["output_response"])
                except Exception:
                    pass
        return {"history": rows}
    except Exception as e:
        return {"history": [], "error": str(e)}


@router.post("/investigate")
def investigate_alert_legacy(req: InvestigateAlertRequest):
    """Legacy alert investigation endpoint for AI Alerts page."""
    alert_dict = req.dict()
    return llm_analyst.generate_investigation_report(alert_dict)


@router.post("/ioc/analyze")
def analyze_ioc_with_ai(req: AnalyzeIocRequest):
    """Analyzes an IOC using the NVIDIA NIM Gateway with verified Threat Intelligence evidence."""
    return llm_gateway.analyze_ioc(req.dict())


@router.post("/incident/investigate")
def investigate_incident_with_ai(req: InvestigateIncidentRequest):
    """Generates an evidence-grounded incident response plan using NVIDIA NIM."""
    return llm_gateway.investigate_incident(req.dict())


@router.post("/case/summarize")
@router.post("/case/report")
def summarize_case_with_ai(req: SummarizeCaseRequest):
    """Synthesizes case timeline, linked incidents, and evidence into an Executive Report."""
    return llm_gateway.summarize_case(req.dict())
