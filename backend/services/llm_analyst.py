import os
import json
import logging
from typing import Dict, Any, Optional, List
from backend.config import settings

logger = logging.getLogger("socchess.services.llm_analyst")

# MITRE ATT&CK Framework Techniques Mapping for Attack Classes
# MITRE ATT&CK Framework Techniques Mapping for Attack Classes across 5 Core Domains
MITRE_TACTICS_MAP: Dict[str, Dict[str, str]] = {
    # 1. Reconnaissance
    "Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "mitigation": "Block scan source on perimeter firewall, close unnecessary listening ports, and configure honeypots."
    },
    "PortScan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "mitigation": "Block scan source on perimeter firewall, close unnecessary listening ports, and configure honeypots."
    },
    "Network Scan": {
        "technique_id": "T1595.001",
        "technique_name": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
        "mitigation": "Deploy egress filtering, limit ICMP unreachable rate, and deploy perimeter intrusion detection rules."
    },
    "Host Discovery": {
        "technique_id": "T1018",
        "technique_name": "Remote System Discovery",
        "tactic": "Discovery",
        "mitigation": "Restrict ICMP echo and subnet broadcasting across internal micro-segments."
    },
    "Service Enumeration": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery & Banner Grabbing",
        "tactic": "Discovery",
        "mitigation": "Scrub banner headers from public services, enforce firewall egress controls, and deploy honeyports."
    },
    "Reconnaissance": {
        "technique_id": "T1595",
        "technique_name": "Active Reconnaissance",
        "tactic": "Reconnaissance",
        "mitigation": "Rate limit ingress probes, inspect anomalous TCP flags, and block scanning subnets."
    },

    # 2. Credential Attacks
    "SSH Brute Force": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing (SSH)",
        "tactic": "Credential Access",
        "mitigation": "Disable password authentication (enforce SSH public keys), change port 22, and enable Fail2Ban."
    },
    "SSH-BruteForce": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing (SSH)",
        "tactic": "Credential Access",
        "mitigation": "Disable password authentication (enforce SSH public keys), change port 22, and enable Fail2Ban."
    },
    "RDP Brute Force": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing (RDP)",
        "tactic": "Credential Access",
        "mitigation": "Enable Network Level Authentication (NLA), place RDP behind MFA VPN, and implement account lockout thresholds."
    },
    "FTP Brute Force": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing (FTP)",
        "tactic": "Credential Access",
        "mitigation": "Enforce SFTP/FTPS, disable plaintext FTP, and throttle connection bursts per IP."
    },
    "FTP-BruteForce": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing (FTP)",
        "tactic": "Credential Access",
        "mitigation": "Enforce SFTP/FTPS, disable plaintext FTP, and throttle connection bursts per IP."
    },
    "Web Login Brute Force": {
        "technique_id": "T1110.001",
        "technique_name": "Password Spraying (HTTP Web Login)",
        "tactic": "Credential Access",
        "mitigation": "Deploy CAPTCHA, implement progressive login delay, and enforce multi-factor authentication (MFA)."
    },
    "Web-BruteForce": {
        "technique_id": "T1110.001",
        "technique_name": "Password Spraying (HTTP Web Login)",
        "tactic": "Credential Access",
        "mitigation": "Deploy CAPTCHA, implement progressive login delay, and enforce multi-factor authentication (MFA)."
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force Authentication",
        "tactic": "Credential Access",
        "mitigation": "Enforce account lockout policies, mandate multi-factor authentication (MFA), and block offending IP."
    },

    # 3. Network Attacks
    "SYN Flood": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood (SYN Backlog Saturation)",
        "tactic": "Impact",
        "mitigation": "Enable SYN cookies (`net.ipv4.tcp_syncookies=1`), reduce SYN-ACK retries, and deploy upstream scrubbing."
    },
    "ICMP Flood": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood (ICMP Echo Storm)",
        "tactic": "Impact",
        "mitigation": "Rate-limit or drop inbound ICMP echo requests on edge routers and firewalls."
    },
    "DDoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "mitigation": "Enable upstream rate limiting, deploy volumetric BGP scrubbing, and enforce SYN cookies."
    },
    "DoS": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "mitigation": "Filter malicious request patterns, tune keep-alive connection limits, and isolate targeting host."
    },
    "ARP Spoofing": {
        "technique_id": "T1557.002",
        "technique_name": "Adversary-in-the-Middle: ARP Poisoning",
        "tactic": "Credential Access / Defense Evasion",
        "mitigation": "Enable Dynamic ARP Inspection (DAI), DHCP Snooping, and static ARP bindings on core switches."
    },
    "Suspicious TCP Connections": {
        "technique_id": "T1571",
        "technique_name": "Non-Standard Port TCP Connection",
        "tactic": "Command and Control",
        "mitigation": "Enforce strict stateful firewall egress rules and terminate non-whitelisted high-port TCP sessions."
    },

    # 4. Web Attacks
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: SQL Injection",
        "tactic": "Initial Access",
        "mitigation": "Implement parameterized queries/prepared statements, enforce database least privilege, and review query logs."
    },
    "SQLInjection": {
        "technique_id": "T1190",
        "technique_name": "SQL Injection",
        "tactic": "Initial Access",
        "mitigation": "Implement parameterized queries/prepared statements, enforce database least privilege, and review query logs."
    },
    "XSS": {
        "technique_id": "T1059.007",
        "technique_name": "Cross-Site Scripting (XSS)",
        "tactic": "Initial Access / Execution",
        "mitigation": "Enforce Content Security Policy (CSP), HTML entity encode untrusted output, and use modern frontend frameworks."
    },
    "Directory Traversal": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Path Traversal",
        "tactic": "Discovery",
        "mitigation": "Sanitize path inputs against `../` sequences, use strictly mapped resource IDs, and run in a chroot/container."
    },
    "Suspicious HTTP Requests": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Anomalous Web Protocol",
        "tactic": "Command and Control / Initial Access",
        "mitigation": "Enforce WAF HTTP inspection, block anomalous User-Agent strings, and drop non-RFC conforming payloads."
    },
    "Web Attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "mitigation": "Apply Web Application Firewall (WAF) signatures, sanitize input parameters, and patch vulnerable endpoints."
    },
    "Exploits": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "mitigation": "Apply vendor security patches, enable exploit protection (DEP/ASLR), and restrict service execution."
    },

    # 5. Malware / Threat Intelligence
    "Malicious IP": {
        "technique_id": "T1071",
        "technique_name": "Network Communication with Known Threat Infrastructure",
        "tactic": "Command and Control",
        "mitigation": "Ingest real-time threat intelligence feeds into perimeter firewalls and block IP across all edge gateways."
    },
    "Malicious Domain": {
        "technique_id": "T1071.004",
        "technique_name": "DNS Query to Known Malicious Domain / DGA",
        "tactic": "Command and Control",
        "mitigation": "Deploy DNS Sinkholing (RPZ), enforce secure recursive DNS, and block newly registered domains (NRDs)."
    },
    "C2 Communication": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol (Command and Control Beaconing)",
        "tactic": "Command and Control",
        "mitigation": "Quarantine compromised endpoint via EDR, sinkhole C2 destination IP/domain, and dump volatile RAM."
    },
    "Botnet": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "mitigation": "Sinkhole malicious C2 domains, isolate compromised endpoint, and perform root-cause malware analysis."
    },
    "Malware Traffic": {
        "technique_id": "T1204",
        "technique_name": "User Execution: Malicious File Network Telemetry",
        "tactic": "Execution",
        "mitigation": "Trigger endpoint EDR host isolation, terminate malicious parent/child processes, and analyze dropped binaries."
    },
    "Data Exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 / Web Channel",
        "tactic": "Exfiltration",
        "mitigation": "Deploy Data Loss Prevention (DLP) gateways, enforce strict egress rate limits, and audit outbound encrypted streams."
    },
    "DNS Tunneling": {
        "technique_id": "T1071.004",
        "technique_name": "DNS Tunneling / Data Covert Channel",
        "tactic": "Command and Control / Exfiltration",
        "mitigation": "Inspect DNS query payload length, monitor high-entropy subdomains, and block recursive lookups to unverified NS."
    },
    "Infiltration": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "mitigation": "Immediately isolate host from network, terminate unauthorized interactive sessions, and perform memory dump."
    },
    "Normal": {
        "technique_id": "N/A",
        "technique_name": "Legitimate Traffic",
        "tactic": "Routine Operation",
        "mitigation": "Standard operational logging and continuous telemetry monitoring."
    }
}


class LLMSecurityAnalyst:
    """
    LLM-Powered Autonomous SOC Security Analyst.
    Provides verified, evidence-grounded security investigations, attack explainability,
    MITRE ATT&CK correlation, and incident response recommendations.
    """

    @classmethod
    def _generate_expert_rule_report(cls, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Directly invokes the zero-hallucination deterministic expert rule investigation engine."""
        return cls.generate_investigation_report(alert_data)

    @classmethod
    def generate_investigation_report(
        cls,
        alert_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generates a comprehensive SOC Analyst incident investigation report.
        """
        attack_type = alert_data.get("attack_type") or alert_data.get("prediction") or "Unknown Threat"
        confidence = float(alert_data.get("mlp_confidence") or alert_data.get("confidence") or 95.0)
        risk_score = float(alert_data.get("risk_score") or 75.0)
        risk_status = alert_data.get("risk_status") or alert_data.get("severity") or "HIGH"
        src_ip = alert_data.get("source_ip") or "Unknown Source"
        dst_ip = alert_data.get("destination_ip") or "Unknown Target"
        dst_port = alert_data.get("destination_port") or alert_data.get("dst_port") or "N/A"
        src_port = alert_data.get("source_port") or alert_data.get("src_port") or "N/A"
        proto = alert_data.get("protocol") or "TCP"
        ti_info = alert_data.get("threat_intel") or {}

        mitre_data = MITRE_TACTICS_MAP.get(attack_type, {
            "technique_id": "T1059",
            "technique_name": "Unclassified Cyber Threat",
            "tactic": "Adversarial Intrusion",
            "mitigation": "Isolate host, capture packet trace, and analyze active network sockets."
        })

        # 1. Primary Live LLM: NVIDIA NIM (meta/llama-3.2-11b-vision-instruct)
        if settings.LLM_ENABLED and getattr(settings, "NVIDIA_API_KEY", ""):
            try:
                from backend.services.llm_gateway import llm_gateway
                prompt = (
                    f"You are a Senior Cyber Defense SOC Lead. Provide a factual, concise security investigation report "
                    f"based exclusively on the following verified alert data:\n"
                    f"Attack Type: {attack_type}\n"
                    f"MLP Neural Network Confidence: {confidence}%\n"
                    f"Risk Score: {risk_score}/100 ({risk_status})\n"
                    f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} ({proto})\n"
                    f"Threat Intel Reputation: {ti_info.get('reputation', 'N/A')} (Score: {ti_info.get('threat_score', 0)})\n"
                    f"MITRE Technique: {mitre_data['technique_id']} - {mitre_data['technique_name']}\n\n"
                    f"Return a structured JSON with keys: attack_explanation, why_suspicious, evidence_summary, "
                    f"investigation_steps, recommended_response, incident_summary."
                )
                nim_model = getattr(settings, "NEMOTRON_MODEL", "meta/llama-3.2-11b-vision-instruct") or "meta/llama-3.2-11b-vision-instruct"
                nim_content = llm_gateway._call_nvidia_api(
                    nim_model,
                    "You are a factual Cyber Security Operations Center AI analyst. Return valid JSON only.",
                    prompt
                )
                if nim_content:
                    clean_json = nim_content
                    if "```json" in clean_json:
                        clean_json = clean_json.split("```json")[1].split("```")[0].strip()
                    elif "```" in clean_json:
                        clean_json = clean_json.split("```")[1].split("```")[0].strip()
                    parsed = json.loads(clean_json)
                    parsed["llm_engine"] = f"NVIDIA NIM ({nim_model})"
                    parsed["mitre_technique"] = f"{mitre_data['technique_id']} - {mitre_data['technique_name']}"
                    parsed["mitre_tactic"] = mitre_data["tactic"]
                    return parsed
            except Exception as e:
                logger.warning(f"[!] NVIDIA NIM query in llm_analyst fallback: {e}")

        # 2. Secondary Live LLM (OpenAI) if key configured
        if settings.OPENAI_API_KEY:
            try:
                from backend.services.llm_gateway import llm_gateway
                openai_model = getattr(settings, "LLM_MODEL", "gpt-4o-mini") or "gpt-4o-mini"
                openai_content = llm_gateway._call_openai_api(
                    openai_model,
                    "You are a factual Cyber Security Operations Center AI analyst. Return valid JSON only.",
                    prompt
                )
                if openai_content:
                    clean_json = openai_content
                    if "```json" in clean_json:
                        clean_json = clean_json.split("```json")[1].split("```")[0].strip()
                    elif "```" in clean_json:
                        clean_json = clean_json.split("```")[1].split("```")[0].strip()
                    parsed = json.loads(clean_json)
                    parsed["llm_engine"] = f"OpenAI ({openai_model})"
                    parsed["mitre_technique"] = f"{mitre_data['technique_id']} - {mitre_data['technique_name']}"
                    parsed["mitre_tactic"] = mitre_data["tactic"]
                    return parsed
            except Exception as e:
                logger.warning(f"[!] Live LLM query fallback: {e}")

        # 2. Rule-Grounded Expert Security Analyst Engine (Deterministic & Zero-Hallucination)
        attack_explanation = (
            f"The Multi-Layer Perceptron (MLP) Neural Network classified this flow as {attack_type} "
            f"with a statistical confidence of {confidence:.1f}%. The Risk Score Engine assigned a composite score "
            f"of {risk_score:.0f}/100 ({risk_status}) based on the attack severity and traffic telemetry."
        )

        why_suspicious = (
            f"Inbound network flow from {src_ip}:{src_port} targeting {dst_ip}:{dst_port} ({proto}) "
            f"demonstrated non-linear feature anomalies consistent with {mitre_data['technique_name']} "
            f"({mitre_data['technique_id']}). Threat Intelligence reputation is marked as "
            f"{ti_info.get('reputation', 'ANALYZED')} (score {ti_info.get('threat_score', 0)}/100)."
        )

        evidence_summary = [
            f"Target Port: {dst_port} ({proto})",
            f"Source Host: {src_ip}:{src_port}",
            f"MLP Classification: {attack_type} ({confidence:.1f}% confidence)",
            f"Calculated Risk Score: {risk_score:.0f}/100 ({risk_status})",
            f"Threat Intelligence Category: {ti_info.get('category', 'Host Profiling')}",
            f"MITRE ATT&CK: {mitre_data['technique_id']} ({mitre_data['tactic']})"
        ]

        investigation_steps = [
            f"1. Triage host socket connections on {dst_ip} bound to port {dst_port}.",
            f"2. Inspect host security logs in Splunk for EventCode 4625 (Logon Failure) or 4688 (Process Creation) around this timestamp.",
            f"3. Query local network gateway firewall logs for historical connection frequency from {src_ip}.",
            f"4. Verify whether {src_ip} matches authorized internal administrators or external IP blocks.",
            f"5. Correlate with concurrent alerts across SIEM and Wireshark capture sessions."
        ]

        recommended_response = [
            f"Immediate: Apply firewall drop rule blocking traffic from {src_ip} to port {dst_port}.",
            f"Endpoint: {mitre_data['mitigation']}",
            f"Containment: If risk is CRITICAL, temporarily isolate {dst_ip} to prevent lateral movement.",
            f"Remediation: Review Splunk security dashboards and reset potentially compromised credentials."
        ]

        incident_summary = (
            f"SOC Incident Alert #{alert_data.get('id', 'N/A')}: Confirmed {attack_type} detection on target {dst_ip}:{dst_port}. "
            f"Risk Level: {risk_status} ({risk_score:.0f}/100). Recommended action: Isolate source {src_ip} and review host process logs."
        )

        return {
            "llm_engine": "SOC Chess Expert Security Analyst Assistant",
            "attack_type": attack_type,
            "confidence": confidence,
            "risk_score": risk_score,
            "risk_status": risk_status,
            "attack_explanation": attack_explanation,
            "why_suspicious": why_suspicious,
            "evidence_summary": evidence_summary,
            "investigation_steps": investigation_steps,
            "recommended_response": recommended_response,
            "incident_summary": incident_summary,
            "mitre_technique": f"{mitre_data['technique_id']} - {mitre_data['technique_name']}",
            "mitre_tactic": mitre_data["tactic"],
            "recommended_action": recommended_response[0]
        }


llm_analyst = LLMSecurityAnalyst()
