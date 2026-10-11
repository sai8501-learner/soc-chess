"""
Test Suite 6: Security Report Generation & Multi-Format Export
Tests report compilation and export to JSON, Markdown, TXT, CSV, and PDF.
"""
import json
import pytest
from fastapi import HTTPException
from backend.routers.cases import (
    generate_and_save_report, export_report, list_reports,
    GenerateReportRequest
)

def test_report_generation_and_exports():
    # 1. Generate Report
    req = GenerateReportRequest(
        report_type="SOC_CASE_REPORT",
        title="Executive Security Audit: Attack Incident Analysis",
        reference_id="CASE-AUDIT-001",
        summary="Automated test report covering threat containment and forensic metrics.",
        content={
            "attack_type": "DDoS",
            "risk_score": 88.0,
            "status": "CONTAINED",
            "evidence_count": 5
        },
        generated_by="SOC Test Suite"
    )
    gen = generate_and_save_report(req)
    assert gen["status"] == "SUCCESS"
    rep_id = gen["report_id"]
    assert rep_id.startswith("REP-")

    # 2. Export JSON
    res_json = export_report(rep_id, format="json")
    if hasattr(res_json, "body"):
        data = json.loads(res_json.body.decode("utf-8"))
    else:
        data = res_json
    assert data["report_id"] == rep_id

    # 3. Export Markdown
    res_md = export_report(rep_id, format="markdown")
    content_md = res_md.body.decode("utf-8")
    assert "# Executive Security Audit" in content_md
    assert "## Executive Summary" in content_md

    # 4. Export TXT
    res_txt = export_report(rep_id, format="txt")
    content_txt = res_txt.body.decode("utf-8")
    assert "SOC CHESS SECURITY REPORT" in content_txt
    assert rep_id in content_txt

    # 5. Export CSV
    res_csv = export_report(rep_id, format="csv")
    content_csv = res_csv.body.decode("utf-8")
    assert "field,value" in content_csv
    assert rep_id in content_csv

    # 6. Export PDF
    res_pdf = export_report(rep_id, format="pdf")
    pdf_bytes = res_pdf.body
    assert len(pdf_bytes) > 50
    assert b"SOC CHESS" in pdf_bytes or b"%PDF" in pdf_bytes

def test_invalid_export_format():
    req = GenerateReportRequest(
        report_type="TEST_REPORT",
        title="Test Report",
        summary="Testing invalid export"
    )
    gen = generate_and_save_report(req)
    rep_id = gen["report_id"]

    with pytest.raises(HTTPException) as excinfo:
        export_report(rep_id, format="unsupported_format_xyz")
    assert excinfo.value.status_code == 400
