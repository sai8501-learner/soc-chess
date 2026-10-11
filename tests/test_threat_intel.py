"""
Test Suite 12: Threat Intelligence & Reputation Feeds
Tests IP reputation lookups, local cache scoring, and categorization.
"""
import pytest
from backend.services.threat_intel import threat_intel_service, KNOWN_IOC_DATABASE

def test_known_malicious_ip_lookup():
    data = threat_intel_service.lookup_ip("192.168.56.104")
    assert data["ip"] == "192.168.56.104"
    assert data["threat_score"] >= 90
    assert data["reputation"] == "MALICIOUS"
    assert data["is_malicious"] is True

def test_known_clean_ip_lookup():
    data = threat_intel_service.lookup_ip("8.8.8.8")
    assert data["ip"] == "8.8.8.8"
    assert data["threat_score"] == 0
    assert data["reputation"] == "CLEAN"
    assert data["is_malicious"] is False

def test_cache_fallback():
    assert "192.168.56.104" in KNOWN_IOC_DATABASE
    assert KNOWN_IOC_DATABASE["192.168.56.104"]["reputation"] == "MALICIOUS"
