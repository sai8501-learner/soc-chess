import json
import time
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.database import query, query_one, execute
from backend.services.llm_analyst import llm_analyst
from backend.services.threat_intel import threat_intel_service
from backend.ml_engine.risk_engine import risk_engine

router = APIRouter(prefix="/api/alerts", tags=["SOC Alerts & AI Investigations"])
logger = logging.getLogger("socchess.alerts")


VALID_INCIDENT_STATUSES = ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]


class CreateAlertRequest(BaseModel):
    source_ip: str = Field(default="192.168.56.104")
    destination_ip: str = Field(default="192.168.56.107")
    source_port: Optional[int] = 50000
    destination_port: Optional[int] = 4444
    protocol: Optional[str] = "TCP"
    attack_type: str = "Infiltration"
    confidence: Optional[float] = 96.4
    mlp_confidence: Optional[float] = 96.4
    risk_score: Optional[float] = 91.0
    risk_status: Optional[str] = "CRITICAL"
    severity: Optional[str] = "CRITICAL"
    source: str = "NETWORK"
    status: Optional[str] = "NEW"
    investigation_status: Optional[str] = "NEW"
    recommended_action: Optional[str] = "Isolate Host and Block Source Port"
    evidence: Optional[Dict[str, Any]] = None
    threat_intel: Optional[Dict[str, Any]] = None
    llm_explanation: Optional[str] = None
    spark_job_id: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None


class UpdateAlertStatusRequest(BaseModel):
    status: str = Field(..., description="NEW, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED, or CLOSED")
    analyst_notes: Optional[str] = None
    assigned_analyst: Optional[str] = "Senior SOC Analyst"


@router.get("")
def get_alerts(limit: int = 100, source: Optional[str] = None, severity: Optional[str] = None, status: Optional[str] = None):
    """Retrieves threat alerts with MLP confidence, Risk Score, Threat Intel, and LLM analysis."""
    try:
        sql = "SELECT * FROM ai_alerts"
        params = []
        conds = []
        if source:
            conds.append("source = %s")
            params.append(source)
        if severity:
            conds.append("(severity = %s OR risk_status = %s)")
            params.extend([severity, severity])
        if status:
            conds.append("(status = %s OR investigation_status = %s)")
            params.extend([status, status])

        if conds:
            sql += " WHERE " + " AND ".join(conds)

        sql += " ORDER BY id DESC LIMIT %s"
        params.append(min(limit, 500))

        rows = query(sql, tuple(params))

        # Parse JSON fields safely
        for r in rows:
            for json_f in ["evidence", "threat_intel", "raw_event"]:
                if r.get(json_f) and isinstance(r[json_f], str):
                    try:
                        r[json_f] = json.loads(r[json_f])
                    except Exception:
                        pass
        return {"alerts": rows}
    except Exception as e:
        logger.warning(f"[!] Error fetching alerts: {e}")
        return {"alerts": []}


@router.get("/summary/stats")
@router.get("/summary")
def get_alerts_summary():
    """Returns comprehensive alert statistics by severity, risk status, attack type, source, and incident lifecycle."""
    try:
        severities = query("SELECT severity, COUNT(*) as count FROM ai_alerts GROUP BY severity")
        risk_statuses = query("SELECT risk_status, COUNT(*) as count FROM ai_alerts GROUP BY risk_status")
        lifecycle_stats = query("SELECT investigation_status, COUNT(*) as count FROM ai_alerts GROUP BY investigation_status")
        sources = query("SELECT source, COUNT(*) as count FROM ai_alerts GROUP BY source")
        attack_types = query("SELECT attack_type, COUNT(*) as count FROM ai_alerts GROUP BY attack_type ORDER BY count DESC LIMIT 10")
        top_ips = query("SELECT source_ip, COUNT(*) as count FROM ai_alerts WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY count DESC LIMIT 10")
        total_rows = query("SELECT COUNT(*) as count FROM ai_alerts")
        total = total_rows[0]["count"] if total_rows else 0

        by_sev = {r["severity"]: r["count"] for r in severities}
        critical_count = by_sev.get("CRITICAL", 0)
        high_count = by_sev.get("HIGH", 0)
        medium_count = by_sev.get("MEDIUM", 0)
        low_count = by_sev.get("LOW", 0)

        return {
            "total_alerts": total,
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "medium_alerts": medium_count,
            "low_alerts": low_count,
            "by_severity": by_sev,
            "by_risk_status": {r["risk_status"]: r["count"] for r in risk_statuses},
            "by_lifecycle": {r["investigation_status"]: r["count"] for r in lifecycle_stats},
            "by_source": {r["source"]: r["count"] for r in sources},
            "top_attack_types": attack_types,
            "top_source_ips": top_ips
        }
    except Exception as e:
        logger.warning(f"[!] Error fetching alerts summary: {e}")
        return {
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "by_severity": {},
            "by_risk_status": {},
            "by_lifecycle": {},
            "by_source": {},
            "top_attack_types": [],
            "top_source_ips": []
        }


@router.get("/{alert_id}")
def get_alert_detail(alert_id: int):
    """Fetches full detail and LLM investigation summary for a single alert."""
    row = query_one("SELECT * FROM ai_alerts WHERE id = %s", (alert_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    for json_f in ["evidence", "threat_intel", "raw_event"]:
        if row.get(json_f) and isinstance(row[json_f], str):
            try:
                row[json_f] = json.loads(row[json_f])
            except Exception:
                pass
    return row


@router.patch("/{alert_id}/status")
@router.post("/{alert_id}/status")
def update_alert_status(alert_id: int, req: UpdateAlertStatusRequest):
    """Updates the SOC incident lifecycle status (NEW -> ACKNOWLEDGED -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED)."""
    clean_stat = req.status.strip().upper()
    if clean_stat not in VALID_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid incident status: '{req.status}'. Must be one of {VALID_INCIDENT_STATUSES}"
        )

    row = query_one("SELECT id, status, investigation_status FROM ai_alerts WHERE id = %s", (alert_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    update_ts = time.strftime("%Y-%m-%d %H:%M:%S")
    note_entry = f"[{update_ts}] Status changed to {clean_stat} by {req.assigned_analyst or 'Analyst'}. Notes: {req.analyst_notes or 'No notes provided.'}"

    try:
        execute("""
            UPDATE ai_alerts
            SET status = %s, investigation_status = %s
            WHERE id = %s
        """, (clean_stat, clean_stat, alert_id))
    except Exception as e:
        logger.error(f"[!] Error updating alert status: {e}")
        raise HTTPException(status_code=500, detail=f"Database update failed: {str(e)}")

    return {
        "status": "updated",
        "alert_id": alert_id,
        "new_status": clean_stat,
        "updated_at": update_ts,
        "note": note_entry
    }


@router.post("/{alert_id}/investigate")
def run_alert_llm_investigation(alert_id: int):
    """Triggers the LLM SOC Analyst Assistant to generate an investigation report for an alert."""
    row = query_one("SELECT * FROM ai_alerts WHERE id = %s", (alert_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Threat Intel lookup if missing
    ti = row.get("threat_intel")
    if not ti and row.get("source_ip"):
        ti = threat_intel_service.lookup_ip(row["source_ip"])

    report = llm_analyst.generate_investigation_report({
        "id": alert_id,
        "attack_type": row.get("attack_type", "Unknown Threat"),
        "mlp_confidence": float(row.get("mlp_confidence") or row.get("confidence") or 95.0),
        "risk_score": float(row.get("risk_score") or 75.0),
        "risk_status": row.get("risk_status") or row.get("severity") or "HIGH",
        "source_ip": row.get("source_ip"),
        "destination_ip": row.get("destination_ip"),
        "source_port": row.get("source_port"),
        "destination_port": row.get("destination_port"),
        "protocol": row.get("protocol"),
        "threat_intel": ti
    })

    # Update alert in database
    try:
        execute("""
            UPDATE ai_alerts
            SET llm_explanation = %s, threat_intel = %s, investigation_status = 'INVESTIGATING'
            WHERE id = %s
        """, (
            report.get("incident_summary", ""),
            json.dumps(ti) if ti else None,
            alert_id
        ))
    except Exception as e:
        logger.warning(f"[!] Warning updating alert investigation in DB: {e}")

    return {"alert_id": alert_id, "investigation": report}


@router.post("")
def create_alert(req: CreateAlertRequest):
    """Records a new Spark + MLP verified threat alert in MySQL."""
    try:
        ti = req.threat_intel or threat_intel_service.lookup_ip(req.source_ip)
        risk_calc = risk_engine.calculate_risk(
            attack_type=req.attack_type,
            mlp_confidence=req.mlp_confidence or req.confidence or 95.0,
            is_attack=True,
            threat_intel_score=float(ti.get("threat_score", 0)),
            destination_ip=req.destination_ip
        )

        final_risk = req.risk_score or risk_calc["risk_score"]
        final_status = req.risk_status or risk_calc["risk_status"]
        inc_status = req.investigation_status or req.status or "NEW"

        alert_id = execute("""
            INSERT INTO ai_alerts (
                source_ip, destination_ip, source_port, destination_port, protocol,
                attack_type, confidence, mlp_confidence, risk_score, risk_status, severity,
                source, status, investigation_status, recommended_action, evidence, threat_intel, llm_explanation, spark_job_id, raw_event
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            req.source_ip, req.destination_ip, req.source_port, req.destination_port, req.protocol,
            req.attack_type, req.confidence or 95.0, req.mlp_confidence or req.confidence or 95.0,
            final_risk, final_status, final_status,
            req.source, inc_status, inc_status, req.recommended_action or "Review host flow",
            json.dumps(req.evidence or {}), json.dumps(ti),
            req.llm_explanation or f"Classified by 3-Hidden-Layer MLP as {req.attack_type}.",
            req.spark_job_id, json.dumps(req.raw_event or {})
        ))
        return {"status": "created", "alert_id": alert_id, "risk_score": final_risk, "risk_status": final_status, "lifecycle_status": inc_status}
    except Exception as e:
        logger.error(f"[!] Error creating alert: {e}")
        return {"status": "error", "message": str(e), "alert_id": None}


