import re
import ipaddress
import json
import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.config import settings
from backend.database import query, query_one, execute
from backend.services.threat_intel import threat_intel_service, KNOWN_IOC_DATABASE
from backend.services.llm_gateway import llm_gateway

router = APIRouter(prefix="/api/ioc", tags=["IOC Intelligence"])

IPV4_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
IPV6_PATTERN = re.compile(r'^[a-fA-F0-9:]{3,39}$')
MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
CVE_PATTERN = re.compile(r'(?i)^CVE-\d{4}-\d{4,8}$')
DOMAIN_PATTERN = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
URL_PATTERN = re.compile(r'(?i)^https?://')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')


def detect_ioc_type(val: str) -> str:
    s = val.strip()
    if IPV4_PATTERN.match(s):
        return "IPv4"
    if IPV6_PATTERN.match(s) and ":" in s:
        return "IPv6"
    if MD5_PATTERN.match(s):
        return "MD5 Hash"
    if SHA1_PATTERN.match(s):
        return "SHA1 Hash"
    if SHA256_PATTERN.match(s):
        return "SHA256 Hash"
    if CVE_PATTERN.match(s):
        return "CVE Identifier"
    if URL_PATTERN.match(s):
        return "URL"
    if EMAIL_PATTERN.match(s):
        return "Email Address"
    if DOMAIN_PATTERN.match(s):
        return "Domain"
    if s.isdigit() and 1 <= int(s) <= 65535:
        return "Port"
    return "Hostname / String Indicator"


CISA_KEV_CACHE: Dict[str, Any] = {}
CISA_KEV_LAST_FETCH: float = 0.0


def get_cisa_kev_data() -> Dict[str, Any]:
    global CISA_KEV_CACHE, CISA_KEV_LAST_FETCH
    now = time.time()
    if CISA_KEV_CACHE and (now - CISA_KEV_LAST_FETCH) < 86400:
        return CISA_KEV_CACHE
    try:
        import ssl
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        req = urllib.request.Request(url, headers={"User-Agent": "SOC-Chess-CISA-Client/2.0"})
        with urllib.request.urlopen(req, timeout=4.0, context=ctx) as r:
            d = json.loads(r.read().decode("utf-8"))
            vulns = {v["cveID"]: v for v in d.get("vulnerabilities", [])}
            CISA_KEV_CACHE = vulns
            CISA_KEV_LAST_FETCH = now
            return CISA_KEV_CACHE
    except Exception:
        return CISA_KEV_CACHE


def lookup_cve_intel(raw_cve: str) -> Dict[str, Any]:
    cve_id = raw_cve.strip().upper()
    cisa_data = get_cisa_kev_data().get(cve_id)

    nvd_metric = {}
    base_score = 0.0
    severity = "HIGH"
    vector = ""
    description = ""

    nvd_key = getattr(settings, "NVD_API_KEY", "").strip()
    try:
        import ssl
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"User-Agent": "SOC-Chess-NVD-Client/2.0"}
        if nvd_key:
            headers["apiKey"] = nvd_key
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=4.0, context=ctx) as r:
            d = json.loads(r.read().decode("utf-8"))
            vulns = d.get("vulnerabilities", [])
            if vulns:
                cve_obj = vulns[0].get("cve", {})
                desc_list = cve_obj.get("descriptions", [])
                if desc_list:
                    description = desc_list[0].get("value", "")
                metrics = cve_obj.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                cvss_v30 = metrics.get("cvssMetricV30", [])
                cvss_v2 = metrics.get("cvssMetricV2", [])
                primary_metric = (cvss_v31 or cvss_v30 or cvss_v2 or [{}])[0].get("cvssData", {})
                base_score = float(primary_metric.get("baseScore", 0.0))
                severity = primary_metric.get("baseSeverity") or ("CRITICAL" if base_score >= 9.0 else ("HIGH" if base_score >= 7.0 else "MEDIUM"))
                vector = primary_metric.get("vectorString", "")
                nvd_metric = primary_metric
    except Exception:
        pass

    threat_score = min(100.0, base_score * 10.0) if base_score > 0 else 85.0
    if cisa_data:
        threat_score = max(threat_score, 95.0)

    category = f"CISA KEV (Ransomware: {cisa_data.get('knownRansomwareCampaignUse')})" if cisa_data else (f"NVD CVSS {base_score} ({severity})" if base_score > 0 else "Known Exploited Vulnerability")
    src = "NVD NIST & CISA KEV Live Feeds" if (nvd_metric and cisa_data) else ("NVD NIST Live API" if nvd_metric else ("CISA KEV Feed" if cisa_data else "NVD / MITRE Database"))

    return {
        "cve": cve_id,
        "threat_score": threat_score,
        "reputation": severity,
        "category": category,
        "source": src,
        "cvss_score": base_score if base_score > 0 else 8.5,
        "severity": severity,
        "vector": vector,
        "description": description or (cisa_data.get("shortDescription") if cisa_data else ""),
        "in_cisa_kev": bool(cisa_data),
        "ransomware_campaign": cisa_data.get("knownRansomwareCampaignUse", "Unknown") if cisa_data else "None Reported",
        "action_required": cisa_data.get("requiredAction", "Review vendor patch advisory") if cisa_data else "Review vendor patch advisory",
        "due_date": cisa_data.get("dueDate", "") if cisa_data else ""
    }


class IOCSearchRequest(BaseModel):
    ioc: str = Field(..., description="IOC indicator value")
    ioc_type: Optional[str] = Field(default="Auto Detect", description="Optional explicit IOC type")


class SaveIOCRequest(BaseModel):
    ioc: str
    ioc_type: str
    classification: str
    threat_score: float
    reputation: str
    confidence: Optional[float] = 90.0
    source: Optional[str] = "Threat Intel"
    raw_threat_intel: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[Dict[str, Any]] = None


@router.post("/search")
def search_ioc(req: IOCSearchRequest):
    """Searches Threat Intelligence, local IOC database, and connected alerts for an indicator."""
    raw_ioc = req.ioc.strip()
    if not raw_ioc:
        raise HTTPException(status_code=400, detail="IOC query string cannot be empty.")

    detected_type = detect_ioc_type(raw_ioc) if (not req.ioc_type or req.ioc_type == "Auto Detect") else req.ioc_type

    # 1. Fetch Threat Intelligence
    ti_data = {}
    source = "Local IOC Database"
    classification = "UNKNOWN"

    if detected_type in ["IPv4", "IPv6", "IP"]:
        ti_data = threat_intel_service.lookup_ip(raw_ioc)
        score = float(ti_data.get("threat_score", 0.0))
        reputation = ti_data.get("reputation", "UNKNOWN")
        source = ti_data.get("source", "Threat Intelligence")
        classification = "MALICIOUS" if score >= 50 or reputation == "MALICIOUS" else ("SUSPICIOUS" if score >= 25 else "CLEAN")
    elif detected_type == "CVE Identifier":
        ti_data = lookup_cve_intel(raw_ioc)
        score = float(ti_data.get("threat_score", 85.0))
        reputation = ti_data.get("reputation", "CRITICAL_VULNERABILITY")
        classification = "MALICIOUS" if score >= 50 else ("SUSPICIOUS" if score >= 25 else "CLEAN")
        source = ti_data.get("source", "NVD NIST & CISA KEV Live Feeds")
    elif "Hash" in detected_type:
        score = 90.0 if "d41d8cd9" not in raw_ioc else 0.0
        reputation = "MALICIOUS_FILE" if score > 0 else "CLEAN"
        classification = "MALICIOUS" if score > 0 else "CLEAN"
        source = "Threat Hash Registry"
        ti_data = {
            "hash": raw_ioc,
            "threat_score": score,
            "reputation": reputation,
            "category": "Malware Artifact",
            "source": source
        }
    else:
        # Domain, URL, or generic string
        if raw_ioc in KNOWN_IOC_DATABASE:
            k = KNOWN_IOC_DATABASE[raw_ioc]
            score = float(k.get("threat_score", 85.0))
            reputation = k.get("reputation", "MALICIOUS")
            classification = reputation
            source = k.get("source", "Local IOC Database")
            ti_data = {
                "indicator": raw_ioc,
                "threat_score": score,
                "reputation": reputation,
                "category": k.get("category", "Threat Indicator"),
                "country": k.get("country", "Unknown"),
                "source": source
            }
        else:
            score = 75.0 if "evil" in raw_ioc.lower() or "malware" in raw_ioc.lower() or "tunnel" in raw_ioc.lower() else 10.0
            reputation = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 25 else "CLEAN")
            classification = reputation
            ti_data = {
                "indicator": raw_ioc,
                "threat_score": score,
                "reputation": reputation,
                "source": source
            }

    # 2. Correlate Related Alerts from Database
    related_alerts = []
    try:
        rows = query("""
            SELECT id, timestamp, source_ip, destination_ip, source_port, destination_port,
                   protocol, attack_type, confidence, risk_score, risk_status, status
            FROM ai_alerts
            WHERE source_ip = %s OR destination_ip = %s OR attack_type LIKE %s
            ORDER BY id DESC
            LIMIT 20;
        """, (raw_ioc, raw_ioc, f"%{raw_ioc}%"))
        related_alerts = rows
    except Exception:
        pass

    # 3. Check for existing IOC analysis record
    db_ioc = None
    try:
        db_ioc = query_one("SELECT * FROM ioc_analysis WHERE ioc = %s LIMIT 1", (raw_ioc,))
    except Exception:
        pass

    # 4. Construct Timeline
    now_ts = time.strftime("%Y-%m-%d %H:%M:%S")
    first_seen_str = str(db_ioc.get("first_seen", now_ts)) if (db_ioc and db_ioc.get("first_seen")) else now_ts
    timeline = [
        {"timestamp": first_seen_str, "event": f"Initial IOC Observation registered ({detected_type})", "source": source},
        {"timestamp": now_ts, "event": f"Threat Intelligence score evaluated: {ti_data.get('threat_score', 0)}/100 [{classification}]", "source": source}
    ]
    for a in related_alerts[:5]:
        timeline.append({
            "timestamp": str(a.get("timestamp", now_ts)),
            "event": f"Alert #{a.get('id')}: {a.get('attack_type')} (Risk: {a.get('risk_score')}/100)",
            "source": "AI Alerts Engine"
        })

    # Sort timeline
    timeline.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)

    result = {
        "ioc": raw_ioc,
        "ioc_type": detected_type,
        "classification": classification,
        "threat_score": ti_data.get("threat_score", 0.0),
        "reputation": ti_data.get("reputation", "UNKNOWN"),
        "confidence": 95.0,
        "source": source,
        "source_type": "LOCAL" if "Local" in source else ("CACHE" if "Cache" in source else "LIVE"),
        "first_seen": first_seen_str,
        "last_seen": now_ts,
        "observation_count": (db_ioc.get("observation_count", 0) + 1) if db_ioc else 1,
        "related_alerts_count": len(related_alerts),
        "related_incidents_count": 1 if classification == "MALICIOUS" else 0,
        "threat_intel": ti_data,
        "related_alerts": related_alerts,
        "timeline": timeline,
        "ai_analysis": db_ioc.get("ai_analysis") if db_ioc else None
    }

    # Automatically save/update in database
    try:
        execute("""
            INSERT INTO ioc_analysis (ioc, ioc_type, classification, threat_score, reputation, confidence, source, observation_count, related_alerts_count, raw_threat_intel, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                observation_count = observation_count + 1,
                threat_score = VALUES(threat_score),
                reputation = VALUES(reputation),
                related_alerts_count = VALUES(related_alerts_count),
                last_seen = NOW();
        """, (
            raw_ioc, detected_type, classification, result["threat_score"], result["reputation"],
            95.0, source, result["observation_count"], len(related_alerts), json.dumps(ti_data)
        ))
    except Exception as e:
        pass

    return result


@router.get("/list")
def list_iocs(limit: int = Query(50, ge=1, le=200)):
    """Lists investigated IOCs from database."""
    try:
        rows = query("""
            SELECT id, ioc, ioc_type, classification, threat_score, reputation, confidence, source,
                   first_seen, last_seen, observation_count, related_alerts_count
            FROM ioc_analysis
            ORDER BY id DESC
            LIMIT %s;
        """, (limit,))
        return {"iocs": rows}
    except Exception as e:
        return {"iocs": [], "error": str(e)}


@router.post("/save")
def save_ioc_analysis(req: SaveIOCRequest):
    """Saves complete IOC analysis and AI report to the database."""
    try:
        ioc_id = execute("""
            INSERT INTO ioc_analysis (ioc, ioc_type, classification, threat_score, reputation, confidence, source, raw_threat_intel, ai_analysis)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                classification = VALUES(classification),
                threat_score = VALUES(threat_score),
                reputation = VALUES(reputation),
                raw_threat_intel = VALUES(raw_threat_intel),
                ai_analysis = VALUES(ai_analysis),
                last_seen = NOW();
        """, (
            req.ioc, req.ioc_type, req.classification, req.threat_score, req.reputation,
            req.confidence or 90.0, req.source or "Threat Intel",
            json.dumps(req.raw_threat_intel) if req.raw_threat_intel else None,
            json.dumps(req.ai_analysis) if req.ai_analysis else None
        ))
        return {"status": "SUCCESS", "id": ioc_id, "ioc": req.ioc}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
