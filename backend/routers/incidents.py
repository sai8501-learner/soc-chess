import json
import time
import uuid
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.database import query, query_one, execute

router = APIRouter(prefix="/api/incidents", tags=["Incident Response & Containment"])

WORKFLOW_STAGES = [
    "NEW", "TRIAGE", "INVESTIGATION", "CONTAINMENT", "ERADICATION",
    "RECOVERY", "MONITORING", "RESOLVED", "CLOSED"
]


class CreateIncidentRequest(BaseModel):
    title: str = Field(..., description="Incident title")
    description: Optional[str] = ""
    alert_id: Optional[int] = None
    attack_type: Optional[str] = "DDoS"
    severity: Optional[str] = "HIGH"
    priority: Optional[str] = "P2"
    risk_score: Optional[float] = 75.0
    risk_status: Optional[str] = "HIGH"
    mlp_confidence: Optional[float] = 95.0
    source_ip: Optional[str] = "192.168.56.104"
    destination_ip: Optional[str] = "192.168.56.107"
    source_port: Optional[int] = 0
    destination_port: Optional[int] = 80
    protocol: Optional[str] = "TCP"
    assigned_analyst: Optional[str] = "Senior SOC Analyst"
    threat_intel: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    splunk_evidence: Optional[List[Dict[str, Any]]] = None


class UpdateIncidentStatusRequest(BaseModel):
    status: str = Field(..., description="New workflow status")
    analyst: Optional[str] = "Senior SOC Analyst"
    notes: Optional[str] = ""


class AddTimelineNoteRequest(BaseModel):
    action: str = Field(..., description="Action description")
    analyst: Optional[str] = "Senior SOC Analyst"
    notes: str = Field(..., description="Detailed analyst observation or procedure")


@router.get("")
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500)
):
    """Retrieves filtered incident records along with aggregated SOC KPI metrics."""
    where_clauses = []
    params = []

    if status and status != "ALL":
        where_clauses.append("status = %s")
        params.append(status)
    if severity and severity != "ALL":
        where_clauses.append("severity = %s")
        params.append(severity)
    if attack_type and attack_type != "ALL":
        where_clauses.append("attack_type = %s")
        params.append(attack_type)
    if search:
        where_clauses.append("(incident_id LIKE %s OR title LIKE %s OR source_ip LIKE %s OR destination_ip LIKE %s OR attack_type LIKE %s)")
        q_wild = f"%{search}%"
        params.extend([q_wild, q_wild, q_wild, q_wild, q_wild])

    sql = "SELECT * FROM incident_response"
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)
    sql += " ORDER BY id DESC LIMIT %s;"
    params.append(limit)

    incidents = []
    try:
        incidents = query(sql, tuple(params))
        for inc in incidents:
            for k in ["threat_intel", "evidence", "splunk_evidence", "ai_investigation"]:
                if isinstance(inc.get(k), str):
                    try:
                        inc[k] = json.loads(inc[k])
                    except Exception:
                        pass
    except Exception as e:
        pass

    # Aggregated KPIs
    all_inc = query("SELECT severity, status, attack_type FROM incident_response;") if incidents or True else []
    total = len(all_inc)
    stats = {
        "total": total,
        "open": sum(1 for r in all_inc if r.get("status") in ["NEW", "TRIAGE", "INVESTIGATION"]),
        "critical": sum(1 for r in all_inc if r.get("severity") == "CRITICAL"),
        "high": sum(1 for r in all_inc if r.get("severity") == "HIGH"),
        "medium": sum(1 for r in all_inc if r.get("severity") == "MEDIUM"),
        "low": sum(1 for r in all_inc if r.get("severity") == "LOW"),
        "investigating": sum(1 for r in all_inc if r.get("status") == "INVESTIGATION"),
        "contained": sum(1 for r in all_inc if r.get("status") == "CONTAINMENT"),
        "resolved": sum(1 for r in all_inc if r.get("status") == "RESOLVED"),
        "closed": sum(1 for r in all_inc if r.get("status") == "CLOSED")
    }

    # Chart Distributions
    sev_dist = {}
    atk_dist = {}
    status_dist = {}
    for r in all_inc:
        s = r.get("severity", "LOW")
        sev_dist[s] = sev_dist.get(s, 0) + 1
        a = r.get("attack_type", "Unknown")
        atk_dist[a] = atk_dist.get(a, 0) + 1
        st = r.get("status", "NEW")
        status_dist[st] = status_dist.get(st, 0) + 1

    return {
        "incidents": incidents,
        "kpis": stats,
        "charts": {
            "severity_distribution": [{"name": k, "value": v} for k, v in sev_dist.items()],
            "attack_distribution": [{"name": k, "value": v} for k, v in atk_dist.items()],
            "status_distribution": [{"name": k, "value": v} for k, v in status_dist.items()]
        }
    }


@router.post("")
def create_incident(req: CreateIncidentRequest):
    """Creates a new incident with auto-populated alert telemetry and initializes its audit timeline."""
    inc_num = int(time.time() * 1000) % 1000000
    inc_id = f"INC-{time.strftime('%Y%m%d')}-{inc_num:04d}"

    # Auto-populate from alert if alert_id is provided
    title = req.title
    atk = req.attack_type or "Unknown"
    sev = req.severity or "HIGH"
    risk = req.risk_score or 75.0
    risk_st = req.risk_status or "HIGH"
    conf = req.mlp_confidence or 95.0
    src_ip = req.source_ip or "192.168.56.104"
    dst_ip = req.destination_ip or "192.168.56.107"
    src_p = req.source_port or 0
    dst_p = req.destination_port or 80
    proto = req.protocol or "TCP"
    ti = req.threat_intel or {}
    ev = req.evidence or {}

    if req.alert_id:
        try:
            al = query_one("SELECT * FROM ai_alerts WHERE id = %s LIMIT 1", (req.alert_id,))
            if al:
                atk = al.get("attack_type") or atk
                sev = al.get("severity") or sev
                risk = float(al.get("risk_score") or risk)
                risk_st = al.get("risk_status") or risk_st
                conf = float(al.get("confidence") or conf)
                src_ip = al.get("source_ip") or src_ip
                dst_ip = al.get("destination_ip") or dst_ip
                src_p = al.get("source_port") or src_p
                dst_p = al.get("destination_port") or dst_p
                proto = al.get("protocol") or proto
                if al.get("threat_intel"):
                    ti = json.loads(al["threat_intel"]) if isinstance(al["threat_intel"], str) else al["threat_intel"]
                if al.get("evidence"):
                    ev = json.loads(al["evidence"]) if isinstance(al["evidence"], str) else al["evidence"]
        except Exception:
            pass

    try:
        execute("""
            INSERT INTO incident_response (
                incident_id, title, description, alert_id, attack_type, severity, priority, status,
                risk_score, risk_status, mlp_confidence, source_ip, destination_ip, source_port,
                destination_port, protocol, assigned_analyst, threat_intel, evidence, splunk_evidence
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """, (
            inc_id, title, req.description or "", req.alert_id, atk, sev, req.priority or "P2", "NEW",
            risk, risk_st, conf, src_ip, dst_ip, src_p, dst_p, proto,
            req.assigned_analyst or "Senior SOC Analyst",
            json.dumps(ti), json.dumps(ev), json.dumps(req.splunk_evidence or [])
        ))

        # Add initial timeline log
        execute("""
            INSERT INTO incident_timeline (incident_id, action, old_status, new_status, analyst, notes)
            VALUES (%s, %s, %s, %s, %s, %s);
        """, (
            inc_id, "Incident Created", "NONE", "NEW",
            req.assigned_analyst or "Senior SOC Analyst",
            f"Initial incident created from alert telemetry ({atk} with risk score {risk}/100)."
        ))

        return {"status": "SUCCESS", "incident_id": inc_id, "message": f"Incident {inc_id} successfully registered."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{incident_id}")
def get_incident(incident_id: str):
    """Retrieves full incident details, evidence, and audit timeline."""
    inc = query_one("SELECT * FROM incident_response WHERE incident_id = %s LIMIT 1", (incident_id,))
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    for k in ["threat_intel", "evidence", "splunk_evidence", "ai_investigation"]:
        if isinstance(inc.get(k), str):
            try:
                inc[k] = json.loads(inc[k])
            except Exception:
                pass

    timeline = query("SELECT * FROM incident_timeline WHERE incident_id = %s ORDER BY id DESC;", (incident_id,))

    return {
        "incident": inc,
        "timeline": timeline,
        "workflow_stages": WORKFLOW_STAGES
    }


@router.patch("/{incident_id}/status")
def update_incident_status(incident_id: str, req: UpdateIncidentStatusRequest):
    """Updates the workflow stage of an incident and logs an audit timeline entry."""
    new_st = req.status.upper()
    if new_st not in WORKFLOW_STAGES:
        raise HTTPException(status_code=400, detail=f"Invalid workflow stage '{new_st}'. Valid: {WORKFLOW_STAGES}")

    inc = query_one("SELECT status FROM incident_response WHERE incident_id = %s LIMIT 1", (incident_id,))
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    old_st = inc.get("status", "NEW")
    execute("UPDATE incident_response SET status = %s WHERE incident_id = %s;", (new_st, incident_id))

    execute("""
        INSERT INTO incident_timeline (incident_id, action, old_status, new_status, analyst, notes)
        VALUES (%s, %s, %s, %s, %s, %s);
    """, (
        incident_id, f"Status Transition: {old_st} -> {new_st}",
        old_st, new_st, req.analyst or "Senior SOC Analyst",
        req.notes or f"Workflow progressed to {new_st}."
    ))

    return {"status": "SUCCESS", "incident_id": incident_id, "old_status": old_st, "new_status": new_st}


@router.post("/{incident_id}/timeline")
def add_timeline_note(incident_id: str, req: AddTimelineNoteRequest):
    """Adds a custom analyst action or procedure note to the incident timeline."""
    inc = query_one("SELECT id FROM incident_response WHERE incident_id = %s LIMIT 1", (incident_id,))
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    execute("""
        INSERT INTO incident_timeline (incident_id, action, old_status, new_status, analyst, notes)
        VALUES (%s, %s, %s, %s, %s, %s);
    """, (
        incident_id, req.action, "LOG", "LOG",
        req.analyst or "Senior SOC Analyst", req.notes
    ))

    return {"status": "SUCCESS", "incident_id": incident_id, "action": req.action}


@router.delete("/{incident_id}")
def delete_incident(incident_id: str):
    """Permanently deletes an incident and its timeline entries."""
    existing = query_one("SELECT id, incident_id FROM incident_response WHERE incident_id = %s LIMIT 1", (incident_id,))
    if not existing:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    execute("DELETE FROM incident_timeline WHERE incident_id = %s", (incident_id,))
    execute("DELETE FROM incident_response WHERE incident_id = %s", (incident_id,))

    return {
        "status": "SUCCESS",
        "message": f"Incident '{incident_id}' and associated timeline records deleted successfully.",
        "incident_id": incident_id
    }
