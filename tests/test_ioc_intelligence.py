"""
Test Suite 1: IOC Intelligence & Threat Analysis
Tests IOC indicator detection, normalization, threat lookups, and database persistence.
"""
import pytest
from backend.routers.ioc import detect_ioc_type, search_ioc, save_ioc_analysis, list_iocs, IOCSearchRequest, SaveIOCRequest
from backend.database import query

def test_detect_ioc_types():
    assert detect_ioc_type("192.168.56.104") == "IPv4"
    assert detect_ioc_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "IPv6"
    assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "MD5 Hash"
    assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "SHA256 Hash"
    assert detect_ioc_type("CVE-2021-44228") == "CVE Identifier"
    assert detect_ioc_type("malicious-c2-domain.com") == "Domain"
    assert detect_ioc_type("https://phishing-site.example.com/login") == "URL"
    assert detect_ioc_type("attacker@badactor.org") == "Email Address"
    assert detect_ioc_type("443") == "Port"

def test_ioc_search_malicious_ip():
    req = IOCSearchRequest(ioc="192.168.56.104")
    res = search_ioc(req)
    assert res["ioc"] == "192.168.56.104"
    assert res["ioc_type"] == "IPv4"
    assert res["classification"] == "MALICIOUS"
    assert res["threat_score"] >= 50.0

def test_ioc_search_clean_ip():
    req = IOCSearchRequest(ioc="8.8.8.8")
    res = search_ioc(req)
    assert res["classification"] == "CLEAN"
    assert res["threat_score"] < 25.0

def test_ioc_search_cve():
    req = IOCSearchRequest(ioc="CVE-2021-44228")
    res = search_ioc(req)
    assert res["ioc_type"] == "CVE Identifier"
    assert res["classification"] == "MALICIOUS"
    assert res["threat_score"] >= 80.0

def test_save_and_list_ioc_analysis():
    save_req = SaveIOCRequest(
        ioc="10.99.99.123",
        ioc_type="IPv4",
        classification="SUSPICIOUS",
        threat_score=65.0,
        reputation="SUSPICIOUS",
        confidence=88.5,
        source="Automated Test Suite",
        raw_threat_intel={"test": True, "notes": "Automated verification indicator"}
    )
    res = save_ioc_analysis(save_req)
    assert res["status"] == "SUCCESS"
    assert res["ioc"] == "10.99.99.123"

    listing = list_iocs(limit=50)
    assert "iocs" in listing
    saved_items = [item["ioc"] for item in listing["iocs"]]
    assert "10.99.99.123" in saved_items
