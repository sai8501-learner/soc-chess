import logging
from typing import Dict, Any, Optional, Union
from backend.config import settings

logger = logging.getLogger("socchess.ml.risk_engine")

# Base Severity weights per attack type (0-100) organized by 5 Security Operational Categories
BASE_ATTACK_SEVERITY: Dict[str, float] = {
    # 1. Reconnaissance
    "Port Scan": 55.0,
    "PortScan": 55.0,
    "Network Scan": 52.0,
    "Host Discovery": 45.0,
    "Service Enumeration": 48.0,
    "Reconnaissance": 48.0,

    # 2. Credential Attacks
    "SSH Brute Force": 80.0,
    "SSH-BruteForce": 80.0,
    "RDP Brute Force": 84.0,
    "FTP Brute Force": 72.0,
    "FTP-BruteForce": 72.0,
    "Web Login Brute Force": 76.0,
    "Web-BruteForce": 76.0,
    "Brute Force": 76.0,

    # 3. Network Attacks
    "SYN Flood": 88.0,
    "ICMP Flood": 75.0,
    "DDoS": 92.0,
    "DoS": 75.0,
    "ARP Spoofing": 82.0,
    "Suspicious TCP Connections": 65.0,

    # 4. Web Attacks
    "SQL Injection": 88.0,
    "SQLInjection": 88.0,
    "XSS": 78.0,
    "Directory Traversal": 82.0,
    "Suspicious HTTP Requests": 62.0,
    "Web Attack": 78.0,
    "Exploits": 92.0,

    # 5. Malware / Threat Intelligence
    "Malicious IP": 85.0,
    "Malicious Domain": 85.0,
    "C2 Communication": 96.0,
    "Malware Traffic": 92.0,
    "Data Exfiltration": 95.0,
    "DNS Tunneling": 90.0,
    "Meterpreter Reverse Shell": 98.0,
    "Botnet": 88.0,
    "Infiltration": 95.0,
    "Backdoor": 96.0,
    "Shellcode": 95.0,
    "Worms": 94.0,
    "Fuzzers": 60.0,

    # Baseline & Generic
    "Normal": 5.0,
    "Attack": 70.0,
}

# Criticality weights for target assets
ASSET_CRITICALITY: Dict[str, float] = {
    "192.168.56.107": 1.2, # Production Victim Host
    "127.0.0.1": 1.1,      # Local Host Controller
    "10.0.0.1": 1.3,       # Gateway / Firewall
    "8.8.8.8": 1.0,        # DNS
}


class RiskScoreEngine:
    """
    SOC Risk Score Calculation Engine.
    Calculates a multi-evidence 0–100 Risk Score independent of raw model probabilities.
    
    Factors Evaluated:
      1. Base Attack Category Severity (0-100)
      2. MLP Neural Network Prediction Confidence (0-100)
      3. Threat Intelligence Indicator Score (0-100)
      4. Event Frequency & Repetition Multiplier
      5. Asset / Target Importance Multiplier
      6. Authentication / Connection Failure Indicator
    """

    @classmethod
    def calculate_risk(
        cls,
        attack_type: str,
        mlp_confidence: float,
        is_attack: bool,
        threat_intel_score: float = 0.0,
        event_frequency: int = 1,
        destination_ip: Optional[str] = None,
        failed_auth_count: int = 0,
        extra_evidence: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Computes the final 0–100 risk score and maps to Low / Medium / High / Critical status.
        """
        # If normal traffic with zero malicious indicators
        if not is_attack and threat_intel_score < 20 and failed_auth_count == 0:
            score = min(20.0, max(2.0, (100.0 - mlp_confidence) * 0.15))
            return cls._format_result(score, "Low", "Normal baseline traffic profile.", {
                "base_severity": 5.0,
                "confidence_contribution": round((100.0 - mlp_confidence) * 0.1, 1),
                "ti_contribution": 0.0,
                "frequency_multiplier": 1.0
            })

        # 1. Base Attack Severity
        base_sev = BASE_ATTACK_SEVERITY.get(attack_type, 70.0)

        # 2. Model Confidence Weight (Higher confidence reinforces severity)
        conf_factor = min(1.0, max(0.5, mlp_confidence / 100.0))

        # 3. Frequency / Repetition Multiplier (e.g. repeated connection bursts)
        freq_mult = 1.0
        if event_frequency > 100:
            freq_mult = 1.25
        elif event_frequency > 20:
            freq_mult = 1.15
        elif event_frequency > 5:
            freq_mult = 1.08

        # 4. Asset Criticality
        asset_mult = ASSET_CRITICALITY.get(destination_ip or "", 1.0)

        # 5. Failed Auth Bonus
        auth_penalty = min(25.0, failed_auth_count * 3.5)

        # 6. Threat Intel Score Contribution
        ti_factor = (threat_intel_score / 100.0) * 20.0

        # Composite Calculation:
        # 45% Base Severity + 25% Model Confidence + 15% Threat Intel + Auth Penalty & Multipliers
        raw_score = ((base_sev * 0.45) + (mlp_confidence * 0.25) + ti_factor + auth_penalty) * freq_mult * asset_mult

        # Clamp strictly between 0 and 100
        final_score = round(min(100.0, max(5.0, raw_score)), 1)

        # Map to Configurable Risk Status
        risk_status = cls.score_to_status(final_score)

        evidence_breakdown = {
            "attack_type": attack_type,
            "base_severity": base_sev,
            "mlp_confidence": round(mlp_confidence, 1),
            "threat_intel_score": round(threat_intel_score, 1),
            "event_frequency": event_frequency,
            "failed_auth_count": failed_auth_count,
            "asset_multiplier": asset_mult,
            "frequency_multiplier": freq_mult,
            "raw_calculated_score": round(raw_score, 2)
        }

        explanation = (
            f"Risk Score {final_score}/100 ({risk_status}): Classified as {attack_type} "
            f"by MLP ({mlp_confidence:.1f}% confidence) with TI score of {threat_intel_score:.0f}."
        )

        return cls._format_result(final_score, risk_status, explanation, evidence_breakdown)

    @classmethod
    def score_to_status(cls, score: float) -> str:
        """Maps 0–100 score to configurable risk levels."""
        if score <= settings.RISK_THRESHOLD_LOW_MAX:
            return "LOW"
        elif score <= settings.RISK_THRESHOLD_MED_MAX:
            return "MEDIUM"
        elif score <= settings.RISK_THRESHOLD_HIGH_MAX:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def _format_result(score: float, status: str, explanation: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "risk_score": float(score),
            "risk_status": status.upper(),
            "severity": status.upper(),
            "explanation": explanation,
            "evidence": evidence
        }


risk_engine = RiskScoreEngine()
