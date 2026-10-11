"""
Test Suite 11: Multi-Factor Risk Calculation Engine
Tests 0-100 score synthesis across MLP confidence, attack type, threat intel, and frequency.
"""
import pytest
from backend.ml_engine.risk_engine import RiskScoreEngine, BASE_ATTACK_SEVERITY

def test_base_attack_severities():
    assert BASE_ATTACK_SEVERITY["DDoS"] >= 90.0
    assert BASE_ATTACK_SEVERITY["Meterpreter Reverse Shell"] >= 95.0
    assert BASE_ATTACK_SEVERITY["Normal"] <= 10.0

def test_risk_calculation_normal_traffic():
    result = RiskScoreEngine.calculate_risk(
        attack_type="Normal",
        mlp_confidence=99.0,
        is_attack=False,
        threat_intel_score=0.0
    )
    assert result["risk_score"] <= 20.0
    assert result["risk_status"] == "LOW"

def test_risk_calculation_critical_attack():
    result = RiskScoreEngine.calculate_risk(
        attack_type="DDoS",
        mlp_confidence=98.0,
        is_attack=True,
        threat_intel_score=95.0,
        event_frequency=150,
        destination_ip="192.168.56.107"
    )
    assert result["risk_score"] >= 75.0
    assert result["risk_status"] in ["HIGH", "CRITICAL"]

def test_status_mapping_thresholds():
    assert RiskScoreEngine.score_to_status(85.0) == "CRITICAL"
    assert RiskScoreEngine.score_to_status(65.0) == "HIGH"
    assert RiskScoreEngine.score_to_status(45.0) == "MEDIUM"
    assert RiskScoreEngine.score_to_status(15.0) == "LOW"
