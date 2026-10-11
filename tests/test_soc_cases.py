"""
Test Suite 3: SOC Case Management & Collaboration
Tests case generation, notes thread, evidence vault, and status lifecycles.
"""
import pytest
from fastapi import HTTPException
from backend.routers.cases import (
    create_case, list_cases, get_case_detail, update_case_status,
    add_case_note, attach_case_evidence,
    CreateCaseRequest, UpdateCaseStatusRequest, AddCaseNoteRequest, AttachEvidenceRequest
)

def test_case_management_flow():
    # 1. Create Case
    req = CreateCaseRequest(
        title="Test Investigation: Infiltration Attempt",
        description="Comprehensive audit of suspicious lateral movement",
        priority="HIGH",
        assigned_analyst="SOC Lead",
        related_ioc="192.168.56.104"
    )
    created = create_case(req)
    assert created["status"] == "SUCCESS"
    case_id = created["case_id"]
    assert case_id.startswith("CASE-")

    # 2. Add Analyst Notes
    note_req = AddCaseNoteRequest(
        analyst="Analyst Alice",
        note_type="Forensic Finding",
        note="Host demonstrated beaconing behavior on TCP 4444"
    )
    n_res = add_case_note(case_id, note_req)
    assert n_res["status"] == "SUCCESS"

    # 3. Attach Evidence
    ev_req = AttachEvidenceRequest(
        evidence_type="IOC",
        reference_id="192.168.56.104",
        title="Attacker C2 Address Evidence",
        details={"threat_score": 95, "reputation": "MALICIOUS"}
    )
    ev_res = attach_case_evidence(case_id, ev_req)
    assert ev_res["status"] == "SUCCESS"

    # 4. Update Status
    upd_req = UpdateCaseStatusRequest(
        status="INVESTIGATING",
        analyst="SOC Lead",
        notes="Active investigation underway"
    )
    u_res = update_case_status(case_id, upd_req)
    assert u_res["status"] == "SUCCESS"
    assert u_res["new_status"] == "INVESTIGATING"

    # 5. Fetch Full Case Details
    detail = get_case_detail(case_id)
    assert detail["case"]["case_id"] == case_id
    assert len(detail["notes"]) >= 2
    assert len(detail["evidence"]) >= 1
    assert detail["evidence"][0]["title"] == "Attacker C2 Address Evidence"

def test_case_invalid_status_fails():
    with pytest.raises(HTTPException) as excinfo:
        update_case_status("CASE-DUMMY", UpdateCaseStatusRequest(status="UNKNOWN_STATUS"))
    assert excinfo.value.status_code == 400
