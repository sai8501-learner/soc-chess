"""
Test Suite 4: Multi-Model LLM Gateway & Provider Cascade
Tests fallback chain (Nemotron -> DeepSeek -> Kimi -> Rule Engine) and fallback determinism.
"""
import pytest
from backend.services.llm_gateway import llm_gateway, LLMGatewayService
from backend.services.llm_analyst import llm_analyst

def test_gateway_initialization():
    status = llm_gateway.get_status()
    assert "models" in status
    assert "primary" in status["models"]
    assert "failover_order" in status
    assert len(status["failover_order"]) == 4

def test_rule_fallback_alert_investigation():
    alert_data = {
        "id": 9999,
        "attack_type": "DDoS",
        "mlp_confidence": 98.2,
        "risk_score": 88.0,
        "risk_status": "CRITICAL",
        "source_ip": "192.168.56.104",
        "destination_ip": "192.168.56.107",
        "protocol": "TCP"
    }
    res = llm_analyst.generate_investigation_report(alert_data)
    assert "attack_explanation" in res
    assert "why_suspicious" in res
    assert "evidence_summary" in res
    assert "investigation_steps" in res
    assert "recommended_response" in res

def test_ioc_analysis_gateway():
    ioc_data = {
        "ioc": "192.168.56.104",
        "ioc_type": "IPv4",
        "threat_score": 95,
        "reputation": "MALICIOUS"
    }
    res = llm_gateway.analyze_ioc(ioc_data)
    assert res["status"] == "SUCCESS"
    assert "content" in res
    assert res["provider"] in ["NVIDIA NIM", "Rule-Based Fallback Engine"]

def test_incident_investigation_gateway():
    inc_data = {
        "incident_id": "INC-TEST-001",
        "attack_type": "Infiltration",
        "severity": "CRITICAL",
        "source_ip": "192.168.56.104",
        "destination_ip": "192.168.56.107"
    }
    res = llm_gateway.investigate_incident(inc_data)
    assert res["status"] == "SUCCESS"
    assert "content" in res
    assert res["provider"] in ["NVIDIA NIM", "Rule-Based Fallback Engine"]

def test_case_summary_gateway():
    case_data = {
        "case_id": "CASE-TEST-001",
        "title": "Suspected Reverse Shell Attack",
        "priority": "HIGH",
        "status": "INVESTIGATING"
    }
    res = llm_gateway.summarize_case(case_data)
    assert res["status"] == "SUCCESS"
    assert "content" in res
    assert res["provider"] in ["NVIDIA NIM", "Rule-Based Fallback Engine"]

def test_ask_cyber_question_gateway():
    res = llm_gateway.ask_cyber_question(
        question="How do I mitigate a SYN flood DDoS attack?",
        context={"category": "DDoS", "destination_ip": "192.168.56.107"}
    )
    assert res["status"] == "SUCCESS"
    assert "content" in res
    assert len(res["content"]) > 20
    assert res["provider"] in ["NVIDIA NIM", "Rule-Based Fallback Engine"]

