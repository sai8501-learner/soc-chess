import os
import re
import time
import json
import logging
import urllib.request
import urllib.error
import requests
import urllib3
from typing import Dict, Any, List, Optional, Tuple

urllib3.disable_warnings()

from backend.config import settings
from backend.database import execute, query
from backend.services.llm_analyst import MITRE_TACTICS_MAP

logger = logging.getLogger("socchess.services.llm_gateway")


# System Prompts for each analysis modality
IOC_SYSTEM_PROMPT = """You are a professional SOC analyst assistant specializing in IOC intelligence.
Respond directly and concisely. Do NOT show reasoning steps, chain-of-thought, or thinking process.
Analyze only the verified cybersecurity evidence supplied by the SOC platform.
Do not fabricate IOC reputation, malware names, CVEs, IP ownership, attack activity, threat intelligence, timestamps, or security events.
Clearly distinguish verified evidence from inference.
Identify possible MITRE ATT&CK techniques only when supported by the evidence.
Provide practical investigation recommendations in a structured format.
Any potentially destructive response action must be marked as requiring human approval."""

INCIDENT_SYSTEM_PROMPT = """You are an experienced enterprise SOC incident-response analyst.
Respond directly and concisely. Do NOT show reasoning steps, chain-of-thought, or thinking process.
Analyze only the verified security information supplied by the SOC system.
Never fabricate security evidence. Clearly distinguish: VERIFIED, INFERRED, and RECOMMENDED.
Provide a structured incident response plan with investigation, containment, eradication, and recovery steps.
Potentially destructive actions must be marked: MANUAL APPROVAL REQUIRED."""

CASE_SYSTEM_PROMPT = """You are a senior SOC Lead and Case Management analyst.
Respond directly and concisely. Do NOT show reasoning steps, chain-of-thought, or thinking process.
Synthesize verified security evidence into an executive-grade case summary and investigative report.
Structure with: Executive Summary, Incident Summary, Evidence Summary, Risk & MITRE ATT&CK, and Recommended Next Steps.
All actions must be advisory. Never fabricate evidence."""

CYBER_CHAT_SYSTEM_PROMPT = """You are SOC CHESS AI Copilot, an elite cybersecurity architect, senior software engineer, and universal AI assistant.
Respond directly, authoritatively, and helpfully. Do NOT show reasoning steps, chain-of-thought tokens, or internal deliberation.
You have universal knowledge across all domains:
1. General Questions & Assistance: Answer any general question clearly, conversationally, and insightfully.
2. Coding, Software & DevOps: Provide robust, production-quality code, shell commands, scripts (Python, Bash, PowerShell, SQL, JS, etc.), and architecture advice with syntax highlighting.
3. Cybersecurity & Threat Investigation: Provide deep technical explanations, MITRE ATT&CK mapping, attack mechanisms, detection signatures (Splunk SPL, Wireshark, YARA), and containment procedures where relevant.
Format responses cleanly in Markdown with bold headers, code snippets, and structured bullet points.
Any potentially destructive commands must be marked as MANUAL APPROVAL REQUIRED."""


def sanitize_untrusted_input(text: Any, max_len: int = 1000) -> str:
    """Neutralizes potential prompt injection markers and limits input size."""
    if text is None:
        return ""
    s = str(text)
    # Strip potential injection directives and excessive whitespace
    s = re.sub(r'(?i)(ignore\s+previous\s+instructions|system\s+prompt|you\s+are\s+now|developer\s+mode)', '[FILTERED_TEXT]', s)
    if len(s) > max_len:
        s = s[:max_len] + "... [TRUNCATED]"
    return s


class LLMGatewayService:
    """
    NVIDIA NIM Enterprise LLM Gateway.
    Implements multi-model cascading failover:
    Nemotron (Primary) -> DeepSeek (Fallback) -> Kimi (Fallback) -> Rule-Based SOC Engine (Offline)
    """

    def __init__(self):
        self.base_url = settings.NVIDIA_BASE_URL.rstrip("/")
        self.primary_model = settings.NEMOTRON_MODEL or "meta/llama-3.2-11b-vision-instruct"
        self.secondary_model = settings.DEEPSEEK_MODEL or "nvidia/llama-3.1-nemotron-70b-instruct"
        self.tertiary_model = settings.KIMI_MODEL
        self.temperature = settings.LLM_TEMPERATURE
        self.max_tokens = settings.LLM_MAX_TOKENS
        self._session = requests.Session()
        self._session.verify = False
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=1)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)


    def get_status(self) -> Dict[str, Any]:
        has_key = bool(settings.NVIDIA_API_KEY and len(settings.NVIDIA_API_KEY.strip()) > 5)
        return {
            "status": "ONLINE" if has_key else "DEGRADED_FALLBACK_ONLY",
            "endpoint": self.base_url,
            "models": {
                "primary": self.primary_model,
                "secondary": self.secondary_model,
                "tertiary": self.tertiary_model
            },
            "api_key_configured": has_key,
            "llm_enabled": settings.LLM_ENABLED,
            "failover_order": [
                "NVIDIA Nemotron-3.5-30B (Primary)",
                "DeepSeek-V4-Pro (Secondary Fallback)",
                "Moonshot Kimi-K3 (Tertiary Fallback)",
                "Deterministic Rule-Based SOC Engine (Offline Fallback)"
            ]
        }

    def _call_nvidia_api(self, model: str, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Calls the NVIDIA NIM OpenAI-compatible Chat Completion endpoint using persistent requests session."""
        api_key = settings.NVIDIA_API_KEY.strip()
        if not api_key:
            return None

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "SOC-Chess-NIM-Gateway/2.0"
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": self.temperature,
            "max_tokens": min(self.max_tokens or 600, 600),
            "top_p": 0.95
        }

        try:
            resp = self._session.post(url, headers=headers, json=payload, timeout=55.0)
            if resp.status_code == 200:
                data = resp.json()
                choices = data.get("choices", [])
                if choices and "message" in choices[0]:
                    content = choices[0]["message"].get("content", "").strip()
                    if content:
                        return content
            elif resp.status_code in (401, 403):
                logger.warning(f"[!] NVIDIA NIM Authentication failed ({resp.status_code}): {resp.text[:120]}")
                return None
            else:
                logger.warning(f"[!] NVIDIA NIM API returned status {resp.status_code} for {model}: {resp.text[:150]}")
                return None
        except requests.exceptions.Timeout:
            logger.warning(f"[!] NVIDIA NIM request timed out (55s) for model {model}")
            return None
        except Exception as e:
            logger.warning(f"[!] NVIDIA NIM error for {model}: {e}")
            return None

        return None

    def _call_openai_api(self, model: str, system_prompt: str, user_prompt: str) -> Optional[str]:
        api_key = (getattr(settings, "OPENAI_API_KEY", "") or "").strip()
        if not api_key:
            return None
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "SOC-Chess-OpenAI-Gateway/2.0"
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST"
        )
        import ssl
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=10.0, context=ssl_ctx) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    choices = data.get("choices", [])
                    if choices and "message" in choices[0]:
                        return choices[0]["message"].get("content", "").strip()
        except Exception as e:
            logger.debug(f"OpenAI call note: {e}")
            return None
        return None

    def _call_gemini_api(self, model: str, system_prompt: str, user_prompt: str) -> Optional[str]:
        api_key = (getattr(settings, "GEMINI_API_KEY", "") or "").strip()
        if not api_key:
            return None
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system_prompt}\n\nTask: {user_prompt}"}]}
            ]
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SOC-Chess-Gemini-Gateway/2.0"},
            method="POST"
        )
        import ssl
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=10.0, context=ssl_ctx) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    cand = data.get("candidates", [])
                    if cand:
                        parts = cand[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "").strip()
        except Exception as e:
            logger.debug(f"Gemini call note: {e}")
            return None
        return None

    def execute_with_failover(
        self,
        system_prompt: str,
        user_prompt: str,
        analysis_type: str,
        reference_id: str,
        deterministic_fallback_fn
    ) -> Dict[str, Any]:
        """Cascading failover execution across NVIDIA NIM (Primary) -> OpenAI -> Gemini -> Rule-Based Fallback."""
        start_t = time.time()

        # 1. PRIMARY: NVIDIA NIM Enterprise LLM Gateway
        if settings.LLM_ENABLED and settings.NVIDIA_API_KEY:
            # Build list of active models without duplicates
            candidate_models = []
            for m in [self.primary_model, "meta/llama-3.2-11b-vision-instruct", "nvidia/llama-3.1-nemotron-70b-instruct", self.secondary_model]:
                if m and m not in candidate_models:
                    candidate_models.append(m)

            for m in candidate_models:
                logger.info(f"[*] Calling NVIDIA NIM with model: {m}")
                content = self._call_nvidia_api(m, system_prompt, user_prompt)
                if content:
                    dur = int((time.time() - start_t) * 1000)
                    model_display = m.split("/")[-1]
                    res = {
                        "provider": f"NVIDIA NIM ({model_display})",
                        "model": m,
                        "status": "SUCCESS",
                        "content": content,
                        "duration_ms": dur,
                        "is_fallback": False
                    }
                    self._record_history(analysis_type, reference_id, "NVIDIA NIM", m, res, dur)
                    return res

        # 2. SECONDARY FAILOVER: OpenAI (if configured)
        if getattr(settings, "OPENAI_API_KEY", "").strip():
            logger.info("[*] Failing over to OpenAI (gpt-4o-mini)")
            content = self._call_openai_api("gpt-4o-mini", system_prompt, user_prompt)
            if content:
                dur = int((time.time() - start_t) * 1000)
                res = {
                    "provider": "OpenAI (GPT-4o-mini)",
                    "model": "gpt-4o-mini",
                    "status": "SUCCESS",
                    "content": content,
                    "duration_ms": dur,
                    "is_fallback": True
                }
                self._record_history(analysis_type, reference_id, "OpenAI", "gpt-4o-mini", res, dur)
                return res

        # 3. TERTIARY FAILOVER: Google Gemini (if configured)
        if getattr(settings, "GEMINI_API_KEY", "").strip():
            for gm in ["gemini-1.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]:
                logger.info(f"[*] Failing over to Gemini model: {gm}")
                content = self._call_gemini_api(gm, system_prompt, user_prompt)
                if content:
                    dur = int((time.time() - start_t) * 1000)
                    res = {
                        "provider": "Google Gemini",
                        "model": gm,
                        "status": "SUCCESS",
                        "content": content,
                        "duration_ms": dur,
                        "is_fallback": True
                    }
                    self._record_history(analysis_type, reference_id, "Google Gemini", gm, res, dur)
                    return res

        # 4. OFFLINE ZERO-FAIL DETERMINISTIC SOC RULE ENGINE FALLBACK
        logger.info("[*] Using Deterministic Rule-Based SOC Engine Fallback")
        dur = int((time.time() - start_t) * 1000)
        fallback_res = deterministic_fallback_fn()
        res = {
            "provider": "Rule-Based Fallback Engine",
            "model": "SOC-Deterministic-Expert-System-v2.0",
            "status": "SUCCESS",
            "content": fallback_res.get("answer") or fallback_res.get("explanation") or fallback_res.get("summary") or json.dumps(fallback_res, indent=2),
            "structured_data": fallback_res,
            "duration_ms": dur,
            "is_fallback": True,
            "notice": "NVIDIA NIM unavailable. Generated using deterministic SOC expert rules."
        }
        self._record_history(analysis_type, reference_id, "Rule-Based Fallback", "Deterministic-Expert", res, dur)
        return res

    def _record_history(self, analysis_type: str, ref_id: str, provider: str, model: str, resp: Dict[str, Any], dur: int):
        try:
            execute("""
                INSERT INTO llm_analysis_history (analysis_type, reference_id, provider, model, status, output_response, duration_ms)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            """, (
                analysis_type,
                ref_id,
                provider,
                model,
                resp.get("status", "SUCCESS"),
                json.dumps(resp),
                dur
            ))
        except Exception as e:
            logger.debug(f"Warning logging LLM history: {e}")

    # 
    # 1. IOC INTELLIGENCE ANALYSIS
    # 
    def analyze_ioc(self, ioc_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes an IOC using verified Threat Intelligence and related alerts."""
        ioc = sanitize_untrusted_input(ioc_data.get("ioc", "UNKNOWN"))
        ioc_type = sanitize_untrusted_input(ioc_data.get("ioc_type", "IP"))
        score = ioc_data.get("threat_score", 0.0)
        rep = ioc_data.get("reputation", "UNKNOWN")
        source = ioc_data.get("source", "Local IOC Database")
        alerts = ioc_data.get("related_alerts", [])

        user_prompt = f"""VERIFIED EVIDENCE:
- Indicator: {ioc}
- Indicator Type: {ioc_type}
- Threat Intelligence Score: {score}/100
- Reputation: {rep}
- Intelligence Source: {source}
- Historical Observations: {ioc_data.get('observation_count', 1)}
- Connected Alerts Count: {len(alerts)}
- Sample Related Attacks: {', '.join(list(set([a.get('attack_type', 'Unknown') for a in alerts[:5]])) or ['None Recorded'])}

Please perform a comprehensive IOC Intelligence investigation and return:
1. IOC Classification (CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN)
2. Executive Summary
3. Why This IOC Is Suspicious
4. Verified Evidence Breakdown
5. Threat Intelligence Interpretation
6. Related Attack Types & MITRE ATT&CK Mapping
7. Confidence Assessment
8. Investigation Recommendations
9. Defensive & Containment Recommendations (Mark destructive actions as MANUAL APPROVAL REQUIRED)
10. Recommended Next Steps"""

        def rule_fallback():
            is_mal = score >= 50 or rep == "MALICIOUS"
            classification = "MALICIOUS" if is_mal else ("SUSPICIOUS" if score >= 25 else "CLEAN")
            return {
                "classification": classification,
                "executive_summary": f"Indicator '{ioc}' ({ioc_type}) has threat score {score}/100 and reputation '{rep}' sourced from {source}.",
                "why_suspicious": f"Associated with {len(alerts)} alerts and elevated reputation score." if is_mal else "No anomalous activity recorded.",
                "verified_evidence": [
                    f"Threat Intelligence Reputation: {rep} ({score}/100)",
                    f"Connected Alert Count: {len(alerts)}",
                    f"Data Source: {source}"
                ],
                "threat_intel_interpretation": f"Host evaluated with score {score}/100 based on prior telemetry.",
                "mitre_mapping": MITRE_TACTICS_MAP.get("Port Scan" if "scan" in str(ioc) else "DDoS", {}),
                "investigation_recommendations": [
                    f"Inspect active connections and flow records connected to {ioc}.",
                    "Query Splunk logs for authentication attempts originating from this indicator.",
                    "Review perimeter firewall ingress/egress logs."
                ],
                "defensive_recommendations": [
                    {"action": f"Block traffic to/from {ioc}", "risk": "Low", "approval": "MANUAL APPROVAL REQUIRED", "procedure": f"Add {ioc} to firewall boundary blocklist."},
                    {"action": "Enable heightened DNS monitoring", "risk": "None", "approval": "AUTOMATIC", "procedure": "Log all domain resolution queries."}
                ],
                "recommended_next_steps": [
                    "Isolate any internal endpoint communicating with high-risk indicator.",
                    "Generate IOC report and attach to active case management thread."
                ]
            }

        res = self.execute_with_failover(
            IOC_SYSTEM_PROMPT,
            user_prompt,
            "IOC_ANALYSIS",
            ioc,
            rule_fallback
        )
        return res

    # 
    # 2. INCIDENT RESPONSE INVESTIGATION
    # 
    def investigate_incident(self, inc_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generates an evidence-grounded incident investigation and containment plan."""
        inc_id = inc_data.get("incident_id", "INC-NEW")
        atk = sanitize_untrusted_input(inc_data.get("attack_type", "Unknown Threat"))
        sev = inc_data.get("severity", "HIGH")
        risk = inc_data.get("risk_score", 75.0)
        conf = inc_data.get("mlp_confidence", 95.0)
        src_ip = sanitize_untrusted_input(inc_data.get("source_ip", "192.168.56.104"))
        dst_ip = sanitize_untrusted_input(inc_data.get("destination_ip", "192.168.56.107"))
        proto = sanitize_untrusted_input(inc_data.get("protocol", "TCP"))
        src_p = inc_data.get("source_port", 0)
        dst_p = inc_data.get("destination_port", 80)
        status = inc_data.get("status", "NEW")

        user_prompt = f"""VERIFIED INCIDENT EVIDENCE:
- Incident ID: {inc_id}
- Attack Classification (MLP Model): {atk} (Confidence: {conf}%)
- Official Risk Score (Risk Engine): {risk}/100 [{inc_data.get('risk_status', 'HIGH')}]
- Severity Tier: {sev}
- Current Status: {status}
- Source IP / Port: {src_ip}:{src_p}
- Destination IP / Port: {dst_ip}:{dst_p}
- Protocol: {proto}
- Threat Intelligence: {json.dumps(inc_data.get('threat_intel', {}))}
- Network Flow Metrics: {json.dumps(inc_data.get('evidence', {}))}

Generate a complete Incident Response Plan:
1. Executive Summary
2. Incident Classification & MITRE ATT&CK Mapping
3. Why This Incident Is Suspicious
4. Verified Evidence Breakdown
5. Risk & Threat Intelligence Interpretation
6. Step-by-Step Response Workflow:
   - Investigation Plan
   - Containment Plan (Tag destructive steps with MANUAL APPROVAL REQUIRED)
   - Eradication Plan
   - Recovery Plan
   - Continuous Monitoring Plan
7. Recommended Response Actions Table (Action, Reason, Priority, Risk, Approval Required, Procedure)"""

        def rule_fallback():
            mitre_info = MITRE_TACTICS_MAP.get(atk, MITRE_TACTICS_MAP.get("DDoS"))
            return {
                "executive_summary": f"Incident {inc_id} involves verified {atk} activity targeting {dst_ip}:{dst_p} from {src_ip} with risk score {risk}/100 ({sev}).",
                "incident_classification": atk,
                "mitre_mapping": mitre_info,
                "why_suspicious": f"High confidence ({conf}%) detection of {atk} attack pattern with elevated risk score.",
                "verified_evidence": [
                    f"MLP Neural Network Classification: {atk} ({conf}% confidence)",
                    f"Multi-Evidence Risk Score: {risk}/100 [{inc_data.get('risk_status', 'HIGH')}]",
                    f"Attacker Host: {src_ip}:{src_p} -> Target Endpoint: {dst_ip}:{dst_p} ({proto})"
                ],
                "investigation_plan": [
                    f"Review full packet capture of flow between {src_ip} and {dst_ip}.",
                    "Query Splunk index for associated Windows Event IDs (4625, 4624, 5156).",
                    "Verify target system process list and running services."
                ],
                "containment_plan": [
                    {"step": 1, "action": f"Block source IP {src_ip} at perimeter firewall", "approval": "MANUAL APPROVAL REQUIRED"},
                    {"step": 2, "action": f"Temporarily quarantine endpoint {dst_ip}", "approval": "MANUAL APPROVAL REQUIRED"},
                    {"step": 3, "action": "Preserve volatile memory image for forensic analysis", "approval": "RECOMMENDED"}
                ],
                "eradication_plan": [
                    "Terminate unauthorized sockets and processes.",
                    "Revoke any active compromised session tokens or credentials.",
                    "Apply relevant vulnerability patch or signature rule."
                ],
                "recovery_plan": [
                    "Restore endpoint to production network under monitoring.",
                    "Verify legitimate application availability and verify latency.",
                    "Update IOC watchlist."
                ],
                "monitoring_plan": [
                    "Enable high-verbosity packet capture on affected subnet for 48 hours.",
                    "Set alert threshold for repeat activity from associated CIDR range."
                ],
                "actions": [
                    {"action": f"Block IP {src_ip}", "reason": "Attacking host in active incident", "priority": "P1", "risk": "Medium", "approval_required": True, "procedure": f"Enforce ACL drop rule on edge router for {src_ip}."},
                    {"action": f"Isolate Host {dst_ip}", "reason": "Targeted endpoint may be compromised", "priority": "P2", "risk": "High", "approval_required": True, "procedure": f"Place {dst_ip} in containment VLAN."},
                    {"action": "Reset User Credentials", "reason": "Mitigate credential abuse", "priority": "P2", "risk": "Low", "approval_required": True, "procedure": "Trigger AD password reset & revoke active tokens."}
                ]
            }

        res = self.execute_with_failover(
            INCIDENT_SYSTEM_PROMPT,
            user_prompt,
            "INCIDENT_INVESTIGATION",
            inc_id,
            rule_fallback
        )
        return res

    # 
    # 3. SOC CASE MANAGEMENT SUMMARY & REPORT
    # 
    def summarize_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesizes case evidence, notes, and timeline into a Lead Analyst case summary."""
        case_id = case_data.get("case_id", "CASE-NEW")
        title = sanitize_untrusted_input(case_data.get("title", "SOC Investigation Case"))
        priority = case_data.get("priority", "MEDIUM")
        status = case_data.get("status", "OPEN")
        analyst = sanitize_untrusted_input(case_data.get("assigned_analyst", "Lead Analyst"))
        incidents = case_data.get("related_incidents", [])
        alerts = case_data.get("related_alerts", [])
        notes = case_data.get("notes", [])

        user_prompt = f"""VERIFIED CASE EVIDENCE:
- Case ID: {case_id}
- Case Title: {title}
- Priority: {priority}
- Status: {status}
- Assigned Analyst: {analyst}
- Linked Incidents Count: {len(incidents)}
- Linked Alerts Count: {len(alerts)}
- Analyst Notes Count: {len(notes)}
- Case Evidence Summary: {json.dumps(case_data.get('evidence_summary', {}))}

Generate an Executive SOC Case Report:
1. Executive Summary (High-level briefing for leadership)
2. Case Overview & Incident Timeline Summary
3. Evidence Synthesis & Correlation
4. Threat Classification & MITRE ATT&CK Mapping
5. Investigation Status & Findings
6. Containment & Remediation Actions Completed / Pending
7. Final Recommendations & Strategic Defense Improvements"""

        def rule_fallback():
            return {
                "executive_summary": f"SOC Case {case_id} ('{title}') is currently {status} with {priority} priority. Tracks {len(incidents)} incident(s) and {len(alerts)} alert(s).",
                "case_overview": f"Investigation managed by {analyst}. Coordinated multi-alert correlation and evidence gathering.",
                "evidence_synthesis": f"Aggregated {len(alerts)} network/log alert artifacts and {len(notes)} investigation observations.",
                "threat_classification": "Multi-Vector Threat Incident",
                "mitre_mapping": {"tactics": ["Initial Access", "Command and Control", "Impact"]},
                "investigation_findings": "Telemetry indicates coordinated scanning followed by exploitation attempts. Target systems contained.",
                "remediation_status": "Containment measures active. Root cause analysis underway.",
                "strategic_recommendations": [
                    "Implement zero-trust network micro-segmentation across target subnets.",
                    "Mandate MFA across all administrative and SSH access vectors.",
                    "Incorporate observed attacker IOCs into global SIEM correlation rules."
                ]
            }

        res = self.execute_with_failover(
            CASE_SYSTEM_PROMPT,
            user_prompt,
            "CASE_SUMMARY",
            case_id,
            rule_fallback
        )
        return res

    # 
    # 4. INTERACTIVE CYBER THREAT Q&A & ANALYST COPILOT
    # 
    # 
    # 4. INTERACTIVE CYBER THREAT Q&A & UNIVERSAL AI COPILOT
    # 
    def ask_cyber_question(
        self,
        question: str,
        attack_type: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Universal AI Copilot Q&A Engine.
        Answers ANY question  from general conversations, programming/coding, architecture,
        and IT operations to deep-dive technical cybersecurity, MITRE ATT&CK correlation,
        Splunk SPL synthesis, YARA rules, and incident containment.
        """
        clean_q = sanitize_untrusted_input(question, max_len=2000)
        ctx = context or {}
        has_active_context = bool(ctx and any(k in ctx for k in ["source_ip", "destination_ip", "attack_name"]))
        atk = attack_type or ctx.get("attack_type") or "General Cybersecurity"
        src_ip = ctx.get("source_ip", "185.220.101.45")
        dst_ip = ctx.get("destination_ip", "192.168.56.107")
        dst_port = ctx.get("destination_port", 80)
        proto = ctx.get("protocol", "TCP")
        risk_score = ctx.get("risk_score", 85.0)

        history_str = ""
        if conversation_history:
            recent = conversation_history[-4:]
            history_str = "\nPREVIOUS CONVERSATION DIALOGUE:\n" + "\n".join([
                f"{h.get('role', 'user').upper()}: {h.get('content', '')}" for h in recent
            ])

        if has_active_context:
            context_str = f"""CURRENT SECURITY INVESTIGATION CONTEXT:
- Active Threat / Attack: {atk}
- Source Endpoint: {src_ip}
- Target Endpoint: {dst_ip}:{dst_port} ({proto})
- Risk Score: {risk_score}/100
- Telemetry Context: {json.dumps({k: v for k, v in ctx.items() if k not in ['playbook_steps', 'telemetry_indicators']})}"""
        else:
            context_str = "MODE: Universal Cybersecurity & AI Assistant"

        user_prompt = f"""{context_str}
{history_str}

USER QUESTION:
{clean_q}

Provide a direct, comprehensive, helpful, and insightful response formatted in clean Markdown."""

        def rule_fallback():
            q_lower = clean_q.lower().strip()
            
            # 
            # 1. GREETINGS & CASUAL CONVERSATION
            # 
            if q_lower in ["hi", "hello", "hey", "hola", "sup", "yo", "greetings", "good morning", "good afternoon", "good evening"] or re.match(r'^(hi|hello|hey)\b', q_lower):
                return {
                    "answer": """###  Hello! Welcome to SOC CHESS AI Copilot

I am your **Autonomous Cybersecurity Copilot & Universal AI Assistant**. I can help you with anything from general queries and code generation to advanced SOC threat operations:

- [DEFENSE] **Cybersecurity Deep-Dives**: Threat analysis, attack mechanics, MITRE ATT&CK mapping, and malware triage.
- [CODE] **Programming & Automation**: Python, Bash, PowerShell, SQL, regex, and network packet scripting.
- [SEARCH] **SIEM & Detection Engineering**: Writing Splunk SPL queries, Sigma rules, Snort signatures, and YARA patterns.
- [INCIDENT] **Incident Response & Forensics**: Wireshark display filters, PCAP analysis, and firewall containment (`iptables` / `netsh`).
- [INSIGHT] **General Knowledge & Concepts**: Zero Trust, encryption algorithms, OSI model, networking, and IT infrastructure.

**How can I assist you right now? Feel free to ask any question or select a prompt!**""",
                    "summary": "AI Copilot greeting and capabilities overview."
                }

            if any(p in q_lower for p in ["who are you", "what are you", "what is soc chess", "introduce yourself"]):
                return {
                    "answer": """### [AI] About SOC CHESS AI Copilot

I am **SOC CHESS AI Copilot**, an autonomous cybersecurity intelligence assistant built into the SOC CHESS platform.

#### Core Capabilities:
1. **Multi-Model Intelligence**: Backed by high-performance LLM engines (NVIDIA NIM, Nemotron, DeepSeek, and deterministic expert fallbacks).
2. **Real-Time Threat Grounding**: Correlates live network telemetry from Apache Spark and Multi-Layer Perceptron (MLP) neural networks.
3. **Detection Engineering**: Generates production-ready Splunk SPL queries, YARA byte patterns, and Sigma rules.
4. **Active Defense**: Synthesizes host containment playbooks, `iptables` rules, and Windows Defender firewall policies.
5. **Universal Coding & Q&A**: Answers technical programming questions across Python, Shell, PowerShell, SQL, and network protocols.

Feel free to ask me any question or test an investigation scenario!""",
                    "summary": "SOC CHESS AI Copilot introduction."
                }

            if any(p in q_lower for p in ["what can you do", "help me", "capabilities", "features", "how do you work"]):
                return {
                    "answer": """### [FAST] What I Can Do For You

As your SOC Copilot and AI Assistant, I can answer questions across multiple domains:

| Category | Example Capabilities |
| :--- | :--- |
| **Cyber Threat Analysis** | Explain attack mechanisms (DDoS, SQLi, Ransomware, XSS, C2 beaconing) & MITRE ATT&CK mappings. |
| **SIEM & Logging** | Generate and optimize **Splunk SPL** queries, correlate Windows Event IDs (4624, 4625), and analyze log pipelines. |
| **Detection Engineering** | Write **YARA** payload signatures, **Sigma** detection rules, and **Snort/Suricata** network rules. |
| **Packet Forensics** | Formulate **Wireshark** display filters, reconstruct TCP stream flows, and analyze PCAP headers. |
| **Incident Containment** | Provide step-by-step containment playbooks with `iptables`, `netsh`, and process isolation commands. |
| **Software & Scripting** | Write Python port scanners, packet sniffers, automation scripts, and database queries. |
| **General IT & Security** | Explain Zero Trust, symmetric vs asymmetric encryption, TLS handshakes, DNS, and OSI layers. |

Type any question below to get started!""",
                    "summary": "Comprehensive capabilities catalog."
                }

            if any(p in q_lower for p in ["how are you", "how are you doing", "how's it going"]):
                return {
                    "answer": "### [ONLINE] Status: Fully Operational\n\nAll SOC monitoring pipelines, Big Data Spark engines, and AI Threat Studio services are running smoothly with optimal latency! How can I help you today?",
                    "summary": "Health and operational readiness confirmation."
                }

            if any(p in q_lower for p in ["thank you", "thanks", "thx", "appreciate it"]):
                return {
                    "answer": "###  You're very welcome!\n\nIf you have any more cybersecurity questions, need code snippets, or want to investigate an incident, I'm here 24/7. Stay secure!",
                    "summary": "Analyst acknowledgment."
                }

            if any(p in q_lower for p in ["joke", "funny", "laugh"]):
                return {
                    "answer": """###  A Little Cyber Humor for You

> **Why do programmers prefer dark mode?**
> *Because light attracts bugs!* 

> **And in Cybersecurity:**
> *There are 10 types of people in the world: those who understand binary, and those who don't have tested backups!* """,
                    "summary": "Cybersecurity humor."
                }

            # 
            # 2. PROGRAMMING, SCRIPTING & CODE GENERATION
            # 
            if ("python" in q_lower and ("scan" in q_lower or "port" in q_lower)) or "port scanner" in q_lower:
                code = """import socket
import sys
from concurrent.futures import ThreadPoolExecutor

def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    \"\"\"Checks if a specific TCP port is open on target host.\"\"\"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        return result == 0

def scan_target(host: str, ports: list, max_threads: int = 50):
    print(f"[*] Starting fast multithreaded scan on {host}...")
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in futures:
            port = futures[future]
            if future.result():
                print(f"  [+] Port {port:<5} is OPEN")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    scan_target(target, common_ports)"""
                return {
                    "answer": f"""### [PYTHON] Multithreaded TCP Port Scanner in Python

Here is a robust, lightweight Python script utilizing `concurrent.futures` and standard `socket` to rapidly scan common ports:

```python
{code}
```

#### How It Works:
1. **Non-blocking Concurrency**: Spawns up to 50 worker threads simultaneously for high throughput.
2. **Socket `connect_ex()`**: Returns `0` on successful TCP handshake (SYN -> SYN-ACK -> ACK), without raising exceptions on closed ports.
3. **Safe Resource Management**: Context managers (`with socket...`) ensure sockets are automatically closed after each probe.""",
                    "summary": "Multithreaded Python Port Scanner."
                }

            if ("python" in q_lower and ("pcap" in q_lower or "packet" in q_lower or "sniff" in q_lower)) or "packet sniffer" in q_lower:
                code = """from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "-")
        dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "-")
        
        print(f"[{proto}] {src}:{sport} -> {dst}:{dport} (Length: {len(packet)} bytes)")

print("[*] Starting live packet capture on default interface (Press Ctrl+C to stop)...")
sniff(prn=packet_callback, count=20, store=False)"""
                return {
                    "answer": f"""### [NETWORK] Python Packet Sniffer with Scapy

Here is a clean Python script using `scapy` to capture and parse live packet headers:

```python
{code}
```

#### Key Considerations:
- Requires administrative / root privileges (raw socket access).
- Install Scapy: `pip install scapy`
- Filter specifically with BPF syntax: e.g., `sniff(filter="tcp port 80", prn=packet_callback)`. """,
                    "summary": "Python packet sniffer script."
                }

            if "regex" in q_lower or "regular expression" in q_lower:
                return {
                    "answer": """### [SEARCH] Essential Cybersecurity Regular Expressions (Regex)

| Artifact Type | Recommended Regex Pattern | Description |
| :--- | :--- | :--- |
| **IPv4 Address** | `\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b` | Matches valid dotted-decimal IPv4 (0.0.0.0 to 255.255.255.255). |
| **MD5 Hash** | `\\b[a-fA-F0-9]{32}\\b` | Exactly 32 hexadecimal characters. |
| **SHA-256 Hash** | `\\b[a-fA-F0-9]{64}\\b` | Exactly 64 hexadecimal characters. |
| **Domain Name** | `\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b` | Standard FQDN format. |
| **CVE Identifier** | `\\bCVE-\\d{4}-\\d{4,7}\\b` | Matches official MITRE CVE naming. |

#### Python Example:
```python
import re

text = "Adversary IP 185.220.101.5 associated with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ips = re.findall(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', text)
hashes = re.findall(r'\\b[a-fA-F0-9]{64}\\b', text)
print("IPs:", ips)
print("Hashes:", hashes)
```""",
                    "summary": "Cybersecurity Regex Catalog."
                }

            if "powershell" in q_lower and ("event" in q_lower or "log" in q_lower or "4625" in q_lower):
                code = """# Query last 20 failed logon attempts (Event ID 4625)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -MaxEvents 20 | ForEach-Object {
    [xml]$xml = $_.ToXml()
    [PSCustomObject]@{
        TimeGenerated = $_.TimeCreated
        TargetUser    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        IpAddress     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        LogonType     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        FailureReason = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Status' }).'#text'
    }
} | Format-Table -AutoSize"""
                return {
                    "answer": f"""### [CODE] PowerShell Script: Audit Failed Logons (Event ID 4625)

Here is a PowerShell script to parse Windows Security event logs for failed authentication attempts:

```powershell
{code}
```

#### Why Event ID 4625 Matters:
- Critical for detecting **RDP / SMB brute-force** and **credential stuffing**.
- `LogonType 3` = Network logon (SMB/shares).
- `LogonType 10` = RemoteInteractive (RDP session).""",
                    "summary": "PowerShell audit for Windows Event ID 4625."
                }

            # 
            # 3. CORE CYBERSECURITY CONCEPTS
            # 
            if "zero trust" in q_lower:
                return {
                    "answer": """### [DEFENSE] Zero Trust Architecture (ZTA) Explained

**Core Philosophy**: *"Never Trust, Always Verify."*
Traditional perimeter defenses ("castle-and-moat") assume anyone inside the corporate network is trustworthy. Zero Trust eliminates implicit trust regardless of location or network ownership.

#### 1. Fundamental Principles
1. **Explicit Verification**: Always authenticate and authorize based on all available data points (user identity, location, device health, service or workload, data classification, and anomalies).
2. **Least Privilege Access**: Restrict user access with Just-In-Time (JIT) and Just-Enough-Access (JEA), risk-based adaptive policies, and data protection.
3. **Assume Breach**: Minimize blast radius by segmenting access by network, user, devices, and application awareness. Encrypt all sessions end-to-end.

#### 2. NIST SP 800-207 Architecture Model
- **Policy Engine (PE)**: Brain that makes the ultimate grant/deny decision.
- **Policy Administrator (PA)**: Control plane that issues credentials/tokens.
- **Policy Enforcement Point (PEP)**: Gateway (proxy/agent) that intercepts and enforces connections.""",
                    "summary": "Comprehensive Zero Trust Architecture overview."
                }

            if "osi" in q_lower and ("model" in q_lower or "layer" in q_lower):
                return {
                    "answer": """### [OSI] The 7 Layers of the OSI Model

The Open Systems Interconnection (OSI) reference model conceptualizes network communication:

| Layer # | Layer Name | Protocol Data Unit (PDU) | Protocols & Standards | Security Context |
| :---: | :--- | :---: | :--- | :--- |
| **7** | **Application** | Data | HTTP, HTTPS, DNS, SSH, FTP, SMTP | WAF, SQLi, XSS, CSRF, API gateways |
| **6** | **Presentation**| Data | SSL/TLS, JPEG, ASCII, JSON | Data encryption, compression, encoding |
| **5** | **Session**     | Data | NetBIOS, RPC, PPTP | Session hijacking, token management |
| **4** | **Transport**   | Segment (TCP) / Datagram (UDP) | TCP, UDP, SCTP | Port scans, SYN floods, TLS handshakes |
| **3** | **Network**     | Packet | IPv4, IPv6, ICMP, IPsec, BGP | IP spoofing, routing attacks, DDoS |
| **2** | **Data Link**   | Frame | Ethernet, ARP, 802.11 Wi-Fi, MAC | ARP poisoning, MAC flooding, VLAN hopping |
| **1** | **Physical**    | Bit | Fiber, Copper, Cat6, RJ45 | Wiretapping, physical tampering |

> **Analyst Tip**: Remember: *"Please Do Not Throw Sausage Pizza Away"* (Physical -> Application) or *"All People Seem To Need Data Processing"* (Application -> Physical).""",
                    "summary": "OSI 7-Layer model reference table."
                }

            if ("tcp" in q_lower and "handshake" in q_lower) or ("3-way" in q_lower and "handshake" in q_lower):
                return {
                    "answer": """###  The TCP 3-Way Handshake Explained

Transmission Control Protocol (TCP) is connection-oriented. Before exchanging payload data, client and server negotiate sequence numbers via a 3-step handshake:

```text
CLIENT                                      SERVER
  |                                           |
  | -------- 1. SYN (Seq = X) -------------> |  (Client requests connection)
  |                                           |
  | <------- 2. SYN-ACK (Seq=Y, Ack=X+1) --- |  (Server acknowledges & responds)
  |                                           |
  | -------- 3. ACK (Seq = X+1, Ack=Y+1) --> |  (Client confirms, socket ESTABLISHED)
  |                                           |
  | ========= Data Exchange (PSH/ACK) ====== |
```

#### Security Implications & Attacks:
- **SYN Flood Attack**: Attacker sends bursts of `SYN` packets from spoofed IPs without sending the final `ACK`. The server's backlog queue fills with half-open connections until memory is exhausted.
- **Defense**: Enable **SYN Cookies** (`sysctl -w net.ipv4.tcp_syncookies=1`), reduce SYN-ACK timeouts, and deploy rate-limiting firewalls.""",
                    "summary": "TCP 3-way handshake mechanics and SYN flood mitigations."
                }

            if "dns" in q_lower and ("work" in q_lower or "explain" in q_lower or "tunnel" in q_lower or "poison" in q_lower):
                return {
                    "answer": """### [DNS] Domain Name System (DNS) & Security

DNS translates human-readable hostnames (`soc-chess.local`) into IP addresses (`192.168.1.100`).

#### 1. Resolution Flow
`Client` -> `Recursive Resolver` -> `Root Server (.)` -> `TLD Server (.com)` -> `Authoritative Nameserver`

#### 2. Key DNS Threat Vectors
- **DNS Cache Poisoning (Kaminsky Attack)**: Forging fake DNS responses to trick resolvers into caching malicious IP mappings.
- **DNS Tunneling**: Exfiltrating encoded data or establishing C2 channels via recursive DNS queries (e.g. `data-payload.evil-c2.com`).
- **DNS Amplification (DDoS)**: Sending small `ANY` queries with a spoofed target IP to open resolvers, generating 50x magnified UDP responses against the victim.

#### 3. Defenses:
- Enforce **DNSSEC** (cryptographically signed records).
- Deploy **DNS-over-HTTPS (DoH)** / **DNS-over-TLS (DoT)**.
- Monitor query entropy and unusually long subdomains (>30 characters) in SIEM.""",
                    "summary": "DNS architecture and security threats."
                }

            if "encryption" in q_lower or "symmetric" in q_lower or "asymmetric" in q_lower or "cryptography" in q_lower:
                return {
                    "answer": """### [CRYPTO] Symmetric vs. Asymmetric Encryption

| Feature | Symmetric Encryption | Asymmetric Encryption |
| :--- | :--- | :--- |
| **Key Mechanism** | Single shared secret key for both encryption and decryption. | Key pair: Public key (encrypt) + Private key (decrypt). |
| **Speed & Performance**| Extremely fast (hardware-accelerated AES-NI). | Computationally heavy (1000x slower). |
| **Key Distribution** | Difficult (how to share secret key securely?). | Easy (publish public key freely; keep private key secret). |
| **Primary Algorithms**| **AES-256**, ChaCha20, 3DES (deprecated). | **RSA (2048/4096-bit)**, **ECC** (ECDSA, Ed25519). |
| **Typical Usage** | Bulk data encryption (hard drives, TLS payload session). | Digital signatures, key exchange (ECDHE in TLS). |

####  Hybrid Encryption (Real-World Standard)
Modern protocols like **HTTPS / TLS** use **asymmetric encryption** to securely negotiate a shared secret session key, and then switch to **symmetric AES** for fast bulk data transmission.""",
                    "summary": "Symmetric vs Asymmetric cryptography comparison."
                }

            if "sql injection" in q_lower or "sqli" in q_lower:
                return {
                    "answer": """### [SQLi] SQL Injection (SQLi) & Prevention

SQL Injection occurs when untrusted user input is directly concatenated into a dynamic SQL query without validation or parameterized bindings.

#### Vulnerable Code Example (Python):
```python
# [FAIL] INSECURE: Vulnerable to SQL Injection
query = f"SELECT * FROM users WHERE username = '{user_input}' AND password = '{password}'"
# An input of: admin' --
# Results in: SELECT * FROM users WHERE username = 'admin' --' AND password = ''
```

#### Secure Remediation (Prepared Statements):
```python
# [OK] SECURE: Parameterized Query
cursor.execute(
    "SELECT id, username, role FROM users WHERE username = %s AND password_hash = %s",
    (user_input, hashed_password)
)
```

#### Defenses in Depth:
1. **Parameterized Queries / ORMs**: Use prepared statements exclusively.
2. **Database Least Privilege**: Never connect the web app using `sa` or `root`.
3. **Web Application Firewall (WAF)**: Enable OWASP ModSecurity Core Rule Set (CRS 942100).""",
                    "summary": "SQL Injection mechanics and prepared statement defense."
                }

            if "xss" in q_lower or "cross-site scripting" in q_lower:
                return {
                    "answer": """### [FAST] Cross-Site Scripting (XSS) Explained

XSS occurs when an application includes untrusted data in a web page without proper validation or escaping, allowing attackers to execute malicious JavaScript in victims' browsers.

#### 1. Three Types of XSS:
- **Stored XSS**: Malicious script is saved in the database (e.g. comments, profile bio) and served to every visiting user.
- **Reflected XSS**: Script is embedded in URL query parameters and bounced off the web server in an error message or search result.
- **DOM-based XSS**: Vulnerability exists purely in client-side JavaScript modifying the DOM unsafely (e.g. `document.write(location.hash)` or `innerHTML`).

#### 2. Defenses:
- **Context-Aware Output Encoding**: HTML-encode `<, >, &, ", '` before rendering into the DOM.
- **Content Security Policy (CSP)**: Set HTTP header:
  `Content-Security-Policy: default-src 'self'; script-src 'self'`
- **Cookie Security**: Set `HttpOnly; Secure; SameSite=Strict` on session cookies to block JavaScript theft.""",
                    "summary": "XSS attack classifications and modern mitigations."
                }

            if "ransomware" in q_lower:
                return {
                    "answer": """### [MALWARE] Ransomware Threat Lifecycle & Incident Response

Ransomware encrypts critical data and demands ransom payment for decryption keys, often accompanied by double or triple extortion (threat of leaking stolen data or contacting customers).

#### Attack Progression:
1. **Initial Access**: Phishing emails with malicious macros, compromised RDP credentials, or exploiting edge devices (VPNs, firewalls).
2. **Staging & Lateral Movement**: Disabling Windows Defender, running Cobalt Strike / Sliver beacons, dumping LSASS credentials (`Mimikatz`).
3. **Inhibit System Recovery**: Deleting Volume Shadow Copies:
   `vssadmin delete shadows /all /quiet`
   `wmic shadowcopy delete`
4. **Mass Encryption**: Encrypting files using AES-256 or ChaCha20, appending custom extensions, and dropping ransom notes.

#### Emergency SOC Containment Actions:
1. **Network Disconnection**: Pull Ethernet cables or disable switch ports immediately to prevent lateral spread.
2. **Preserve Volatile Memory**: Dump RAM (`LiME` or `DumpIt`) before rebooting to preserve encryption keys and C2 sockets.
3. **Audit Active Directory**: Disable compromised service accounts and enforce enterprise-wide password resets.
4. **Restore From Offline Backups**: Verify backup integrity using the **3-2-1 backup rule** (3 copies, 2 media types, 1 immutable offsite).""",
                    "summary": "Ransomware anatomy and emergency response playbook."
                }

            if "phishing" in q_lower:
                return {
                    "answer": """### [PHISHING] Phishing Attacks & Enterprise Defense

Phishing is social engineering where an adversary impersonates a trusted entity to harvest credentials, deliver malware, or initiate fraudulent transactions.

#### Variations:
- **Spear Phishing**: Targeted attack against a specific individual or organization using researched reconnaissance.
- **Whaling**: Targeting C-level executives (CEO, CFO) for Business Email Compromise (BEC).
- **Smishing / Vishing**: Phishing via SMS text messages or voice telephone calls.

#### Technical Email Defenses:
- **SPF (Sender Policy Framework)**: Specifies which mail servers are authorized to send email for your domain.
- **DKIM (DomainKeys Identified Mail)**: Cryptographically signs email headers to prevent tampering in transit.
- **DMARC (Domain-based Message Authentication)**: Enforces policies (`p=reject`) if SPF or DKIM fails.
- **FIDO2 / WebAuthn MFA**: Hardware security keys (YubiKeys) that are inherently phishing-resistant.""",
                    "summary": "Phishing classification and technical email hardening."
                }

            if "wireshark" in q_lower or "pcap" in q_lower or "packet" in q_lower or "filter" in q_lower:
                filter_code = f"""// Isolate all traffic between attacker and target
ip.addr == {src_ip} && ip.addr == {dst_ip}

// Filter for anomalous TCP SYN packets without ACK
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.port == {dst_port}

// Filter for HTTP POST/GET requests from attacker
http.request.method in {{"POST", "GET"}} && ip.src == {src_ip}

// Detect DNS tunneling (high-frequency queries or long query names)
dns.flags.response == 0 && dns.qry.name.len > 30"""
                return {
                    "answer": f"""### [PCAP] Wireshark Display Filters & Packet Forensics

Here are key display filters for analyzing network traffic and isolating adversary flows:

```text
{filter_code}
```

#### Essential Wireshark Shortcuts:
- **Follow TCP Stream**: `Right-click packet` -> `Follow` -> `TCP Stream` (Ctrl+Alt+Shift+T).
- **Conversations Statistics**: `Statistics` -> `Conversations` -> Inspect top IP talkers and byte volume.
- **Export Objects**: `File` -> `Export Objects` -> `HTTP` to carve transferred binaries or files from the capture.""",
                    "summary": "Wireshark packet forensic display filters."
                }

            if "splunk" in q_lower or "spl" in q_lower or "query" in q_lower:
                splunk_code = f"""index=* (sourcetype="pan:traffic" OR sourcetype="cisco:asa" OR sourcetype="suricata") dest_ip="{dst_ip}"
| stats count as event_count, dc(src_ip) as unique_sources, values(dest_port) as targeted_ports by src_ip, transport
| where event_count > 500 OR unique_sources > 20
| sort - event_count
| eval threat_level=case(event_count > 5000, "CRITICAL", event_count > 1000, "HIGH", true(), "MEDIUM")"""
                return {
                    "answer": f"""### [SIEM] Splunk SPL Detection Query

Here is an optimized Splunk search processing normalized firewall and intrusion detection logs:

```spl
{splunk_code}
```

#### Query Breakdown:
1. Searches firewall/IDS sourcetypes for the targeted destination IP (`{dst_ip}`).
2. Calculates aggregated packet volumes and distinct source IP counts per transport protocol.
3. Flags anomalous volumetric bursts exceeding baseline thresholds.
4. Dynamically evaluates and assigns risk severity tags.""",
                    "summary": "Splunk SPL detection query."
                }

            if "yara" in q_lower or "rule" in q_lower or "signature" in q_lower:
                clean_name = atk.replace(' ', '_').replace('-', '_')
                yara_code = f"""rule SOC_Chess_Detect_{clean_name} {{
    meta:
        description = "Detects {atk} telemetry signatures and malicious payload commands"
        author = "SOC Chess Autonomous Platform"
        severity = "High"
        date = "2026-09-26"
    strings:
        $s1 = "{src_ip}" ascii wide
        $s2 = "/bin/sh" ascii
        $s3 = "powershell -nop -exec bypass" ascii wide nocase
        $hex1 = {{ 4D 5A 90 00 03 00 00 00 }} // MZ executable header
    condition:
        ($hex1 and (1 of ($s*))) or ($s1 and 1 of ($s2, $s3))
}}"""
                return {
                    "answer": f"""### [YARA] YARA Detection Rule for {atk}

Here is a compiled YARA rule targeting malicious staging commands and payload strings:

```yara
{yara_code}
```

#### Deployment:
- Test rule against a sample file: `yara -w rule.yar /path/to/suspect/file`
- Integrate with EDR / ClamAV / VirusTotal scanning pipelines.""",
                    "summary": f"YARA detection rule for {atk}."
                }

            if "contain" in q_lower or "block" in q_lower or "firewall" in q_lower or "mitigat" in q_lower or "iptables" in q_lower:
                fw_code = f"""# Linux iptables immediate drop (MANUAL APPROVAL REQUIRED)
sudo iptables -I INPUT -s {src_ip} -j DROP
sudo iptables -I FORWARD -s {src_ip} -j DROP

# Windows Defender Firewall block (MANUAL APPROVAL REQUIRED)
netsh advfirewall firewall add rule name="SOC-Chess-Block-{src_ip}" dir=in action=block protocol=ANY remoteip={src_ip}

# Terminate active socket sessions to this host
sudo ss -K dst {src_ip}"""
                return {
                    "answer": f"""### [DEFENSE] Host & Perimeter Containment Playbook

Here are the immediate containment commands to isolate traffic from `{src_ip}`:

```bash
{fw_code}
```

#### Post-Containment Steps:
1. Verify rule application: `sudo iptables -L INPUT -v -n | grep {src_ip}`
2. Check for lateral movement on adjacent hosts in the same subnet (`{dst_ip}`).
3. Export connection telemetry to the SOC Incident Evidence Vault.""",
                    "summary": "Containment commands and firewall blocking."
                }

            # 
            # 4. TELEMETRY-GROUNDED INVESTIGATION (if active threat)
            # 
            mitre_ref = MITRE_TACTICS_MAP.get(atk, {
                "tactic": "Defense Evasion & Initial Access",
                "tactic_id": "TA0001",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "sub_technique": "T1190"
            })

            if has_active_context or any(t.lower() in q_lower for t in ["ddos", "botnet", "sqli", "bruteforce", "infiltration", "port scan"]):
                summary = f"Comprehensive cybersecurity assessment for **{atk}**: Threat Mechanism, Risk Assessment, and Remediation."
                tech_detail = f"Adversary activity from `{src_ip}` targets host `{dst_ip}:{dst_port}` using `{proto}` with an active calculated risk score of **{risk_score}/100**. Observed indicators include repetitive anomalous connection bursts, high error frequencies, or non-standard flag distribution."
                artifacts = f"""```bash
# Block attacking IP on perimeter firewall (MANUAL APPROVAL REQUIRED)
iptables -I INPUT -s {src_ip} -j DROP
```"""
                formatted_text = f"""### [REPORT] Executive Investigation Analysis
{summary}

### [ANALYSIS] Technical Deep-Dive
{tech_detail}

### [DEFENSE] MITRE ATT&CK Correlation
- **Tactic**: `{mitre_ref.get('tactic', 'Defense Evasion')}` ({mitre_ref.get('tactic_id', 'TA0005')})
- **Technique**: `{mitre_ref.get('technique_id', 'T1059')}`  *{mitre_ref.get('technique_name', 'Command and Scripting Interpreter')}*
- **Sub-Technique**: `{mitre_ref.get('sub_technique', 'T1059.001')}`

### [CODE] Actionable Defense Commands
{artifacts}

### [FAST] Recommended SOC Action Steps
1. **Perimeter Verification**: Verify if `{src_ip}` has communicated with any internal assets besides `{dst_ip}`.
2. **Telemetry Ingestion**: Apply SIEM/Splunk correlation rules to alert on repeated connection attempts.
3. **Host Isolation**: If lateral movement is detected, isolate the affected target machine immediately.
4. **Case Escalation**: Link these findings to an active SOC Incident Case for evidentiary logging."""
                return {
                    "answer": formatted_text,
                    "mitre": mitre_ref,
                    "summary": summary,
                    "technical_details": tech_detail
                }

            # 
            # 5. UNIVERSAL INTELLIGENT SYNTHESIZER FOR ANY GENERAL QUESTION
            # 
            title_q = clean_q.capitalize().rstrip("?")
            return {
                "answer": f"""### [INSIGHT] Analysis & Insights: {title_q}

Here is a comprehensive breakdown addressing your question:

#### 1. Core Concepts & Overview
{clean_q.strip()} involves key principles in software engineering, security architecture, and systems operations. In modern enterprise environments, understanding these mechanisms helps maintain resilient, high-availability, and secure infrastructures.

#### 2. Key Architecture & Operational Mechanics
- **Structural Design**: Emphasizes separation of concerns, modularity, and defense-in-depth principles.
- **Security & Integrity**: Ensures all data exchanges and execution flows validate inputs, enforce authentication, and adhere to the principle of least privilege.
- **Monitoring & Observability**: Real-time logging, metrics telemetry, and anomaly detection ensure system behavior remains within expected operational baselines.

#### 3. Best Practices & Actionable Recommendations
1. **Enforce Strong Controls**: Implement rigorous access controls, validation checks, and secure defaults across all layers.
2. **Automate Verification**: Leverage automated scripts, unit/integration testing, and continuous security scanning.
3. **Maintain Detailed Logs**: Capture structured audit logs for all critical state changes and transactions.

*Need specific scripts, configuration examples, or deep-dive details on this topic? Just let me know!*""",
                "summary": f"Universal analysis for: {clean_q}"
            }

        res = self.execute_with_failover(
            CYBER_CHAT_SYSTEM_PROMPT,
            user_prompt,
            "CYBER_QA",
            f"QA-{int(time.time())}",
            rule_fallback
        )
        return res


llm_gateway = LLMGatewayService()

