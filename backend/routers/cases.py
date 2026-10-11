import json
import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from backend.database import query, query_one, execute
from backend.services.llm_gateway import llm_gateway

router = APIRouter(prefix="/api/cases", tags=["SOC Case Management & Reports"])

CASE_STATUSES = ["OPEN", "INVESTIGATING", "PENDING", "RESOLVED", "CLOSED"]
PRIORITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class CreateCaseRequest(BaseModel):
    title: str = Field(..., description="Case investigation title")
    description: Optional[str] = ""
    priority: Optional[str] = "MEDIUM"
    assigned_analyst: Optional[str] = "Lead Threat Analyst"
    related_incident_id: Optional[str] = None
    related_alert_id: Optional[int] = None
    related_ioc: Optional[str] = None


class UpdateCaseStatusRequest(BaseModel):
    status: str
    analyst: Optional[str] = "Lead Threat Analyst"
    notes: Optional[str] = ""


class AddCaseNoteRequest(BaseModel):
    analyst: Optional[str] = "Senior Analyst"
    note_type: Optional[str] = "Investigation Note"
    note: str = Field(..., description="Analyst note or findings")


class AttachEvidenceRequest(BaseModel):
    evidence_type: str = Field(..., description="ALERT, INCIDENT, IOC, SPLUNK, PCAP, CSV, LOG, REPORT")
    reference_id: Optional[str] = None
    title: str
    details: Optional[Dict[str, Any]] = None


class GenerateReportRequest(BaseModel):
    report_type: str = Field(default="SOC_CASE_REPORT", description="SOC_CASE_REPORT, INCIDENT_REPORT, IOC_REPORT, AI_INVESTIGATION_REPORT, EXECUTIVE_REPORT")
    title: str
    reference_id: Optional[str] = None
    content: Optional[Dict[str, Any]] = None
    summary: Optional[str] = None
    generated_by: Optional[str] = "NVIDIA AI SOC Analyst"


@router.get("")
def list_cases(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500)
):
    """Lists SOC Cases with filtering, search, and aggregated status metrics."""
    where = []
    params = []

    if status and status != "ALL":
        where.append("status = %s")
        params.append(status)
    if priority and priority != "ALL":
        where.append("priority = %s")
        params.append(priority)
    if search:
        where.append("(case_id LIKE %s OR title LIKE %s OR related_incident_id LIKE %s OR related_ioc LIKE %s)")
        q_w = f"%{search}%"
        params.extend([q_w, q_w, q_w, q_w])

    sql = "SELECT * FROM soc_cases"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT %s;"
    params.append(limit)

    cases = []
    try:
        cases = query(sql, tuple(params))
        for c in cases:
            if isinstance(c.get("ai_summary"), str):
                try:
                    c["ai_summary"] = json.loads(c["ai_summary"])
                except Exception:
                    pass
    except Exception:
        pass

    all_cases = query("SELECT priority, status FROM soc_cases;") or []
    kpis = {
        "total": len(all_cases),
        "open": sum(1 for c in all_cases if c.get("status") in ["OPEN", "INVESTIGATING"]),
        "investigating": sum(1 for c in all_cases if c.get("status") == "INVESTIGATION" or c.get("status") == "INVESTIGATING"),
        "pending": sum(1 for c in all_cases if c.get("status") == "PENDING"),
        "resolved": sum(1 for c in all_cases if c.get("status") == "RESOLVED"),
        "closed": sum(1 for c in all_cases if c.get("status") == "CLOSED")
    }

    prio_dist = {}
    st_dist = {}
    for c in all_cases:
        p = c.get("priority", "MEDIUM")
        prio_dist[p] = prio_dist.get(p, 0) + 1
        st = c.get("status", "OPEN")
        st_dist[st] = st_dist.get(st, 0) + 1

    return {
        "cases": cases,
        "kpis": kpis,
        "charts": {
            "priority_distribution": [{"name": k, "value": v} for k, v in prio_dist.items()],
            "status_distribution": [{"name": k, "value": v} for k, v in st_dist.items()]
        }
    }


@router.post("")
def create_case(req: CreateCaseRequest):
    """Creates a new SOC Case and automatically attaches linked incident/alert evidence."""
    case_num = int(time.time() * 1000) % 1000000
    case_id = f"CASE-{time.strftime('%Y%m%d')}-{case_num:04d}"

    try:
        execute("""
            INSERT INTO soc_cases (case_id, title, description, priority, status, assigned_analyst, related_incident_id, related_alert_id, related_ioc)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
        """, (
            case_id, req.title, req.description or "", req.priority or "MEDIUM", "OPEN",
            req.assigned_analyst or "Lead Threat Analyst",
            req.related_incident_id, req.related_alert_id, req.related_ioc
        ))

        # Add initial note
        execute("""
            INSERT INTO case_notes (case_id, analyst, note_type, note)
            VALUES (%s, %s, %s, %s);
        """, (
            case_id, req.assigned_analyst or "Lead Threat Analyst", "Case Initialization",
            f"Case opened with {req.priority or 'MEDIUM'} priority. Initial investigation commenced."
        ))

        # Auto-attach evidence if related_incident_id or related_alert_id provided
        if req.related_incident_id:
            execute("""
                INSERT INTO case_evidence (case_id, evidence_type, reference_id, title, details)
                VALUES (%s, %s, %s, %s, %s);
            """, (case_id, "INCIDENT", req.related_incident_id, f"Linked Incident {req.related_incident_id}", json.dumps({"incident_id": req.related_incident_id})))

        if req.related_alert_id:
            execute("""
                INSERT INTO case_evidence (case_id, evidence_type, reference_id, title, details)
                VALUES (%s, %s, %s, %s, %s);
            """, (case_id, "ALERT", str(req.related_alert_id), f"Linked Alert #{req.related_alert_id}", json.dumps({"alert_id": req.related_alert_id})))

        return {"status": "SUCCESS", "case_id": case_id, "message": f"Case {case_id} registered successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{case_id}")
def get_case_detail(case_id: str):
    """Retrieves full case information, analyst notes thread, and linked evidence items."""
    c = query_one("SELECT * FROM soc_cases WHERE case_id = %s LIMIT 1;", (case_id,))
    if not c:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    if isinstance(c.get("ai_summary"), str):
        try:
            c["ai_summary"] = json.loads(c["ai_summary"])
        except Exception:
            pass

    notes = query("SELECT * FROM case_notes WHERE case_id = %s ORDER BY id ASC;", (case_id,))
    evidence = query("SELECT * FROM case_evidence WHERE case_id = %s ORDER BY id DESC;", (case_id,))
    for ev in evidence:
        if isinstance(ev.get("details"), str):
            try:
                ev["details"] = json.loads(ev["details"])
            except Exception:
                pass

    return {
        "case": c,
        "notes": notes,
        "evidence": evidence,
        "statuses": CASE_STATUSES
    }


@router.patch("/{case_id}/status")
def update_case_status(case_id: str, req: UpdateCaseStatusRequest):
    """Updates the status of a SOC Case and records a note."""
    st = req.status.upper()
    if st not in CASE_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status '{st}'. Valid: {CASE_STATUSES}")

    execute("UPDATE soc_cases SET status = %s WHERE case_id = %s;", (st, case_id))

    execute("""
        INSERT INTO case_notes (case_id, analyst, note_type, note)
        VALUES (%s, %s, %s, %s);
    """, (
        case_id, req.analyst or "Lead Analyst", "Status Update",
        req.notes or f"Case status updated to {st}."
    ))

    return {"status": "SUCCESS", "case_id": case_id, "new_status": st}


@router.post("/{case_id}/notes")
def add_case_note(case_id: str, req: AddCaseNoteRequest):
    """Appends an analyst note or observation to the case thread."""
    c = query_one("SELECT id FROM soc_cases WHERE case_id = %s LIMIT 1;", (case_id,))
    if not c:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    execute("""
        INSERT INTO case_notes (case_id, analyst, note_type, note)
        VALUES (%s, %s, %s, %s);
    """, (
        case_id, req.analyst or "Senior Analyst", req.note_type or "Investigation Note", req.note
    ))

    return {"status": "SUCCESS", "case_id": case_id}


@router.post("/{case_id}/evidence")
def attach_case_evidence(case_id: str, req: AttachEvidenceRequest):
    """Attaches an alert, incident, IOC, or log item to the case evidence locker."""
    c = query_one("SELECT id FROM soc_cases WHERE case_id = %s LIMIT 1;", (case_id,))
    if not c:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    execute("""
        INSERT INTO case_evidence (case_id, evidence_type, reference_id, title, details)
        VALUES (%s, %s, %s, %s, %s);
    """, (
        case_id, req.evidence_type.upper(), req.reference_id or "", req.title,
        json.dumps(req.details or {})
    ))

    return {"status": "SUCCESS", "case_id": case_id, "title": req.title}


# ═══════════════════════════════════════════════════════════════
# REPORTS SUITE
# ═══════════════════════════════════════════════════════════════
@router.get("/reports/all")
def list_reports(limit: int = Query(50, ge=1, le=200)):
    """Lists all generated SOC reports from database."""
    try:
        rows = query("""
            SELECT id, report_id, report_type, title, reference_id, summary, generated_by, format, created_at
            FROM reports
            ORDER BY id DESC
            LIMIT %s;
        """, (limit,))
        return {"reports": rows}
    except Exception as e:
        return {"reports": [], "error": str(e)}


@router.post("/reports/generate")
def generate_and_save_report(req: GenerateReportRequest):
    """Generates and persists a formal security report (Executive, Case, Incident, or IOC)."""
    rep_num = int(time.time() * 1000) % 1000000
    rep_id = f"REP-{time.strftime('%Y%m%d')}-{rep_num:04d}"

    content = req.content or {}
    summary = req.summary or content.get("executive_summary") or content.get("summary") or req.title

    try:
        execute("""
            INSERT INTO reports (report_id, report_type, title, reference_id, content, summary, generated_by, format)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """, (
            rep_id, req.report_type, req.title, req.reference_id or "",
            json.dumps(content), summary, req.generated_by or "NVIDIA AI SOC Analyst", "JSON"
        ))

        return {"status": "SUCCESS", "report_id": rep_id, "title": req.title}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/{report_id}")
def get_report(report_id: str):
    """Retrieves single report content."""
    r = query_one("SELECT * FROM reports WHERE report_id = %s LIMIT 1;", (report_id,))
    if not r:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found.")

    if isinstance(r.get("content"), str):
        try:
            r["content"] = json.loads(r["content"])
        except Exception:
            pass

    return {"report": r}


@router.get("/reports/{report_id}/export")
def export_report(report_id: str, format: str = Query("json", description="json, markdown, txt, csv, pdf")):
    """Exports the report content in JSON, Markdown, TXT, CSV, or PDF format."""
    r = query_one("SELECT * FROM reports WHERE report_id = %s LIMIT 1;", (report_id,))
    if not r:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found.")

    raw_content = r.get("content", {})
    if isinstance(raw_content, str):
        try:
            raw_content = json.loads(raw_content)
        except Exception:
            pass

    fmt = format.lower().strip()

    r_clean = {}
    for k, v in r.items():
        if hasattr(v, "isoformat"):
            r_clean[k] = v.isoformat()
        else:
            r_clean[k] = v
    r_clean["content"] = raw_content

    # ── JSON ──────────────────────────────────────────────────────
    if fmt == "json":
        return JSONResponse(
            content=r_clean,
            headers={"Content-Disposition": f'attachment; filename="{report_id}.json"'}
        )

    # ── MARKDOWN ─────────────────────────────────────────────────
    if fmt == "markdown":
        md = f"""# {r.get('title')}
**Report ID**: {r.get('report_id')}
**Report Type**: {r.get('report_type')}
**Generated By**: {r.get('generated_by')}
**Date**: {r.get('created_at')}

---

## Executive Summary
{r.get('summary', 'No summary provided.')}

## Structured Content
```json
{json.dumps(raw_content, indent=2)}
```
"""
        return PlainTextResponse(content=md, media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="{report_id}.md"'})

    # ── TXT ───────────────────────────────────────────────────────
    if fmt == "txt":
        def _flatten(obj, prefix="", lines=None):
            if lines is None:
                lines = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _flatten(v, f"{prefix}{k}.", lines)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    _flatten(v, f"{prefix}[{i}].", lines)
            else:
                lines.append(f"{prefix.rstrip('.')}: {obj}")
            return lines

        sep = "=" * 72
        lines = [
            sep,
            f"SOC CHESS SECURITY REPORT",
            sep,
            f"Report ID    : {r.get('report_id')}",
            f"Title        : {r.get('title')}",
            f"Type         : {r.get('report_type')}",
            f"Generated By : {r.get('generated_by')}",
            f"Date         : {r.get('created_at')}",
            sep,
            "EXECUTIVE SUMMARY",
            "-" * 72,
            r.get('summary', 'No summary provided.'),
            "",
            sep,
            "FULL REPORT CONTENT",
            "-" * 72,
        ]
        lines.extend(_flatten(raw_content))
        lines.append(sep)
        txt = "\n".join(str(l) for l in lines)
        return PlainTextResponse(content=txt, media_type="text/plain",
                                 headers={"Content-Disposition": f'attachment; filename="{report_id}.txt"'})

    # ── CSV ───────────────────────────────────────────────────────
    if fmt == "csv":
        import csv, io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["field", "value"])
        writer.writerow(["report_id", r.get("report_id")])
        writer.writerow(["title", r.get("title")])
        writer.writerow(["report_type", r.get("report_type")])
        writer.writerow(["generated_by", r.get("generated_by")])
        writer.writerow(["created_at", r.get("created_at")])
        writer.writerow(["summary", r.get("summary")])
        writer.writerow([])
        writer.writerow(["content_key", "content_value"])

        def _write_dict(d, prefix=""):
            if isinstance(d, dict):
                for k, v in d.items():
                    _write_dict(v, f"{prefix}{k}.")
            elif isinstance(d, list):
                for i, v in enumerate(d):
                    _write_dict(v, f"{prefix}[{i}].")
            else:
                writer.writerow([prefix.rstrip("."), str(d)])

        _write_dict(raw_content)
        csv_content = buf.getvalue()
        return PlainTextResponse(content=csv_content, media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{report_id}.csv"'})

    # ── PDF ───────────────────────────────────────────────────────
    if fmt == "pdf":
        pdf_bytes = None

        # Attempt 1: fpdf2
        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 10, "SOC CHESS SECURITY REPORT", ln=True, align="C")
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, f"Report ID: {r.get('report_id')}    Type: {r.get('report_type')}", ln=True)
            pdf.cell(0, 6, f"Date: {r.get('created_at')}    By: {r.get('generated_by')}", ln=True)
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "EXECUTIVE SUMMARY", ln=True)
            pdf.set_font("Helvetica", "", 10)
            summary_text = str(r.get("summary", "No summary provided."))
            pdf.multi_cell(0, 6, summary_text)
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "FULL REPORT CONTENT", ln=True)
            pdf.set_font("Courier", "", 8)

            def _pdf_flatten(obj, prefix="", depth=0):
                result = []
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        result.extend(_pdf_flatten(v, f"{prefix}{k}: ", depth + 1))
                elif isinstance(obj, list):
                    for i, v in enumerate(obj):
                        result.extend(_pdf_flatten(v, f"{prefix}[{i}] ", depth + 1))
                else:
                    result.append(f"{prefix}{str(obj)[:200]}")
                return result

            for line in _pdf_flatten(raw_content):
                try:
                    pdf.multi_cell(0, 5, line.encode("latin-1", "replace").decode("latin-1"))
                except Exception:
                    pdf.multi_cell(0, 5, "[non-printable content]")

            pdf_bytes = pdf.output()
        except ImportError:
            pass
        except Exception:
            pass

        # Attempt 2: reportlab
        if not pdf_bytes:
            try:
                from reportlab.lib.pagesizes import A4
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
                from reportlab.lib.styles import getSampleStyleSheet
                import io as _io
                buf2 = _io.BytesIO()
                doc = SimpleDocTemplate(buf2, pagesize=A4)
                styles = getSampleStyleSheet()
                story = [
                    Paragraph("SOC CHESS SECURITY REPORT", styles["Title"]),
                    Paragraph(f"Report ID: {r.get('report_id')}", styles["Normal"]),
                    Paragraph(f"Type: {r.get('report_type')} | Date: {r.get('created_at')}", styles["Normal"]),
                    Spacer(1, 12),
                    Paragraph("Executive Summary", styles["Heading2"]),
                    Paragraph(str(r.get("summary", "No summary.")), styles["Normal"]),
                    Spacer(1, 12),
                    Paragraph("Full Content", styles["Heading2"]),
                    Paragraph(json.dumps(raw_content, indent=2)[:5000], styles["Code"]),
                ]
                doc.build(story)
                pdf_bytes = buf2.getvalue()
            except ImportError:
                pass
            except Exception:
                pass

        # Fallback: TXT rendered as UTF-8 served with PDF content type
        if not pdf_bytes:
            sep = "=" * 72
            fallback_lines = [
                sep, "SOC CHESS SECURITY REPORT", sep,
                f"Report ID    : {r.get('report_id')}",
                f"Title        : {r.get('title')}",
                f"Type         : {r.get('report_type')}",
                f"Generated By : {r.get('generated_by')}",
                f"Date         : {r.get('created_at')}",
                sep, "EXECUTIVE SUMMARY", "-" * 72,
                str(r.get("summary", "No summary provided.")), "",
                sep, "FULL CONTENT", "-" * 72,
                json.dumps(raw_content, indent=2), sep,
            ]
            pdf_bytes = "\n".join(fallback_lines).encode("utf-8")

        from fastapi.responses import Response as FastResponse
        return FastResponse(
            content=pdf_bytes if isinstance(pdf_bytes, bytes) else bytes(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{report_id}.pdf"'}
        )

    raise HTTPException(status_code=400, detail=f"Unsupported format '{fmt}'. Supported: json, markdown, txt, csv, pdf")


@router.delete("/{case_id}")
def delete_case(case_id: str):
    """Permanently deletes a SOC case and its associated evidence and notes."""
    existing = query_one("SELECT id, case_id FROM soc_cases WHERE case_id = %s", (case_id,))
    if not existing:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    execute("DELETE FROM case_notes WHERE case_id = %s", (case_id,))
    execute("DELETE FROM case_evidence WHERE case_id = %s", (case_id,))
    execute("DELETE FROM soc_cases WHERE case_id = %s", (case_id,))

    return {
        "success": True,
        "message": f"Case '{case_id}' and all associated records deleted successfully.",
        "case_id": case_id
    }
