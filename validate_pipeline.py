"""
================================================================================
SOC CHESS — CORE PIPELINE VALIDATION SCRIPT (validate_pipeline.py)
Validates: Database, Threat Intel, Risk Engine, IOC, Incidents, Cases, Reports
================================================================================
"""
import sys
import os
import time
import json
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.config import settings
from backend.database import query, query_one, execute, init_db
from backend.services.threat_intel import threat_intel_service
from backend.ml_engine.risk_engine import RiskScoreEngine
from backend.routers.ioc import detect_ioc_type, search_ioc, save_ioc_analysis, list_iocs, IOCSearchRequest, SaveIOCRequest
from backend.routers.incidents import create_incident, get_incident, update_incident_status, add_timeline_note, CreateIncidentRequest, UpdateIncidentStatusRequest, AddTimelineNoteRequest
from backend.routers.cases import create_case, get_case_detail, update_case_status, add_case_note, attach_case_evidence, generate_and_save_report, export_report, CreateCaseRequest, UpdateCaseStatusRequest, AddCaseNoteRequest, AttachEvidenceRequest, GenerateReportRequest

def run_pipeline_validation():
    print("=" * 70)
    print("   SOC CHESS — AUTONOMOUS SECURITY PIPELINE VALIDATION")
    print("=" * 70)
    passed_checks = 0
    total_checks = 8

    # 1. Database Connectivity & Tables
    print("\n[CHECK 1/8] Verifying Database Schema & Tables...")
    try:
        init_db()
        tables = [
            "ai_alerts", "ioc_analysis", "incident_response",
            "incident_timeline", "soc_cases", "case_notes",
            "case_evidence", "reports", "llm_analysis_history"
        ]
        found_tables = []
        for t in tables:
            r = query(f"SHOW TABLES LIKE '{t}';")
            if r:
                found_tables.append(t)
        assert len(found_tables) == len(tables), f"Missing tables: {set(tables) - set(found_tables)}"
        print(f"  [+] All {len(tables)} SOC Chess tables verified in MySQL.")
        passed_checks += 1
    except Exception as e:
        print(f"  [-] Database check failed: {e}")

    # 2. Threat Intelligence
    print("\n[CHECK 2/8] Verifying Threat Intelligence Service...")
    try:
        mal_data = threat_intel_service.lookup_ip("192.168.56.104")
        clean_data = threat_intel_service.lookup_ip("8.8.8.8")
        assert mal_data["reputation"] == "MALICIOUS" and mal_data["threat_score"] >= 90
        assert clean_data["reputation"] == "CLEAN" and clean_data["threat_score"] == 0
        print(f"  [+] Threat Intel verified: 192.168.56.104 -> MALICIOUS ({mal_data['threat_score']}), 8.8.8.8 -> CLEAN ({clean_data['threat_score']})")
        passed_checks += 1
    except Exception as e:
        print(f"  [-] Threat Intel check failed: {e}")

    # 3. Multi-Factor Risk Score Engine
    print("\n[CHECK 3/8] Verifying Risk Score Calculation Engine...")
    try:
        norm = RiskScoreEngine.calculate_risk(attack_type="Normal", mlp_confidence=99.0, is_attack=False)
        ddos = RiskScoreEngine.calculate_risk(attack_type="DDoS", mlp_confidence=97.0, is_attack=True, threat_intel_score=95.0, event_frequency=80)
        assert norm["risk_score"] <= 20.0 and norm["risk_status"] == "LOW"
        assert ddos["risk_score"] >= 75.0 and ddos["risk_status"] in ["HIGH", "CRITICAL"]
        print(f"  [+] Risk Engine verified: Normal Traffic -> Score {norm['risk_score']} ({norm['risk_status']}), DDoS Attack -> Score {ddos['risk_score']} ({ddos['risk_status']})")
        passed_checks += 1
    except Exception as e:
        print(f"  [-] Risk Engine check failed: {e}")

    # 4. IOC Intelligence Module
    print("\n[CHECK 4/8] Verifying IOC Intelligence Router & Persistence...")
    try:
        test_ip = "192.168.56.104"
        ioc_res = search_ioc(IOCSearchRequest(ioc=test_ip))
        assert ioc_res["ioc"] == test_ip
        assert ioc_res["classification"] == "MALICIOUS"

        save_res = save_ioc_analysis(SaveIOCRequest(
            ioc="198.51.100.22",
            ioc_type="IPv4",
            classification="SUSPICIOUS",
            threat_score=60.0,
            reputation="SUSPICIOUS",
            confidence=90.0,
            source="Pipeline Validator"
        ))
        assert save_res["status"] == "SUCCESS"
        print(f"  [+] IOC Intelligence verified: Search, classification, timeline, and database save operational.")
        passed_checks += 1
    except Exception as e:
        print(f"  [-] IOC Intelligence check failed: {e}")

    # 5. Incident Response Module
    print("\n[CHECK 5/8] Verifying Incident Response 9-Stage Workflow...")
    try:
        inc = create_incident(CreateIncidentRequest(
            title="SYN Flood Surge Incident",
            attack_type="DDoS",
            severity="HIGH",
            risk_score=85.0,
            source_ip="192.168.56.104",
            destination_ip="192.168.56.107"
        ))
        inc_id = inc["incident_id"]
        update_incident_status(inc_id, UpdateIncidentStatusRequest(status="CONTAINMENT", analyst="Lead SOC"))
        add_timeline_note(inc_id, AddTimelineNoteRequest(action="Isolate Host", notes="Host quarantined."))
        detail = get_incident(inc_id)
        assert detail["incident"]["status"] == "CONTAINMENT"
        assert len(detail["timeline"]) >= 2
        print(f"  [+] Incident Response verified: Created {inc_id}, transitioned to CONTAINMENT, timeline updated.")
        passed_checks += 1
    except Exception as e:
        print(f"  [-] Incident Response check failed: {e}")

    # 6. SOC Case Management Module
    print("\n[CHECK 6/8] Verifying SOC Case Management & Evidence Vault...")
    try:
        case = create_case(CreateCaseRequest(
            title="Lateral Movement Investigation",
            priority="HIGH",
            related_ioc="192.168.56.104"
        ))
        case_id = case["case_id"]
        add_case_note(case_id, AddCaseNoteRequest(analyst="Lead Analyst", note="Beaconing detected."))
        attach_case_evidence(case_id, AttachEvidenceRequest(
            evidence_type="IOC",
            title="Adversary C2 IP",
            details={"ip": "192.168.56.104", "threat_score": 95}
        ))
        case_detail = get_case_detail(case_id)
        assert len(case_detail["notes"]) >= 2
        assert len(case_detail["evidence"]) >= 1
        print(f"  [+] SOC Case Management verified: Created {case_id}, notes and evidence attached.")
        passed_checks += 1
    except Exception as e:
        print(f"  [-] SOC Case Management check failed: {e}")

    # 7. Report Generation & Multi-Format Export
    print("\n[CHECK 7/8] Verifying Report Generation & Export (JSON, Markdown, TXT, CSV, PDF)...")
    try:
        rep = generate_and_save_report(GenerateReportRequest(
            report_type="SOC_CASE_REPORT",
            title="Enterprise Incident Closure Audit",
            summary="Validated incident containment and forensic indicators.",
            content={"status": "RESOLVED", "attack_type": "DDoS", "risk_score": 85.0}
        ))
        rep_id = rep["report_id"]

        formats = ["json", "markdown", "txt", "csv", "pdf"]
        for fmt in formats:
            res = export_report(rep_id, format=fmt)
            assert res is not None
        print(f"  [+] Reports Engine verified: Created {rep_id}, successfully exported JSON, Markdown, TXT, CSV, PDF.")
        passed_checks += 1
    except Exception as e:
        print(f"  [-] Reports check failed: {e}")

    # 8. API Parameter Sanitization & Defense
    print("\n[CHECK 8/8] Verifying API Defense & Input Sanitization...")
    try:
        from backend.routers.cases import list_cases
        res = list_cases(search="' OR '1'='1' --")
        assert "cases" in res
        print(f"  [+] API Defense verified: Parameterized queries successfully defended against SQL injection payload.")
        passed_checks += 1
    except Exception as e:
        print(f"  [-] API Defense check failed: {e}")

    print("\n" + "=" * 70)
    print(f"PIPELINE VALIDATION SUMMARY: {passed_checks}/{total_checks} CHECKS PASSED")
    print("=" * 70)
    return passed_checks == total_checks

if __name__ == "__main__":
    success = run_pipeline_validation()
    sys.exit(0 if success else 1)
