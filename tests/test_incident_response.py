"""
Test Suite 2: Incident Response & Containment Workflows
Tests 9-stage lifecycle, incident creation, updates, and forensic timeline logging.
"""
import pytest
from fastapi import HTTPException
from backend.routers.incidents import (
    create_incident, list_incidents, get_incident,
    update_incident_status, add_timeline_note,
    CreateIncidentRequest, UpdateIncidentStatusRequest, AddTimelineNoteRequest,
    WORKFLOW_STAGES
)

def test_incident_lifecycle():
    # 1. Create Incident
    req = CreateIncidentRequest(
        title="Automated Test Incident - DDoS Surge",
        description="High volume SYN flood detected from malicious host",
        attack_type="DDoS",
        severity="HIGH",
        priority="P1",
        risk_score=85.0,
        risk_status="CRITICAL",
        source_ip="192.168.56.104",
        destination_ip="192.168.56.107"
    )
    created = create_incident(req)
    assert created["status"] == "SUCCESS"
    inc_id = created["incident_id"]
    assert inc_id.startswith("INC-")

    # 2. Retrieve detail
    detail = get_incident(inc_id)
    assert detail["incident"]["incident_id"] == inc_id
    assert detail["incident"]["status"] == "NEW"
    assert len(detail["timeline"]) >= 1

    # 3. Transition through stages
    for stage in ["TRIAGE", "INVESTIGATION", "CONTAINMENT", "RESOLVED"]:
        update_req = UpdateIncidentStatusRequest(
            status=stage,
            analyst="Test Lead Analyst",
            notes=f"Transitioning incident to {stage}"
        )
        upd = update_incident_status(inc_id, update_req)
        assert upd["status"] == "SUCCESS"
        assert upd["new_status"] == stage

    # 4. Add custom timeline note
    note_req = AddTimelineNoteRequest(
        action="Isolate Host",
        analyst="Forensic Specialist",
        notes="Applied firewall block rule at boundary gateway"
    )
    note_res = add_timeline_note(inc_id, note_req)
    assert note_res["status"] == "SUCCESS"

    # 5. Verify timeline entries
    final_detail = get_incident(inc_id)
    assert final_detail["incident"]["status"] == "RESOLVED"
    actions = [t["action"] for t in final_detail["timeline"]]
    assert "Isolate Host" in actions

def test_invalid_incident_stage_rejected():
    with pytest.raises(HTTPException) as excinfo:
        update_incident_status("INC-NONEXISTENT", UpdateIncidentStatusRequest(status="SUPER_HERO_STAGE"))
    assert excinfo.value.status_code == 400
