"""
Test Suite 10: NVIDIA NIM LLM Real Integration & Graceful Fallback
Tests whether NVIDIA API Key triggers live inference or safely cascades to offline rule analyst.
"""
import os
import pytest
from backend.config import settings
from backend.services.llm_gateway import llm_gateway

def test_nvidia_key_configuration():
    key = settings.NVIDIA_API_KEY
    assert key is not None
    is_placeholder = key in ["", "PASTE_NEW_KEY_HERE"]
    is_valid_format = key.startswith("nvapi-") or len(key) >= 16

    assert is_placeholder or is_valid_format, "NVIDIA key should either be configured or placeholder"

def test_llm_gateway_end_to_end_resilience():
    incident_payload = {
        "incident_id": "INC-TEST-RESILIENCE",
        "attack_type": "DDoS",
        "mlp_confidence": 97.5,
        "risk_score": 85.0,
        "risk_status": "CRITICAL",
        "source_ip": "192.168.56.104",
        "destination_ip": "192.168.56.107"
    }
    res = llm_gateway.investigate_incident(incident_payload)
    assert res["status"] == "SUCCESS"
    assert "content" in res
    assert res["provider"] in ["NVIDIA NIM", "Rule-Based Fallback Engine", "Local Rules"]
