"""
Test Suite 9: Digital Evidence Cryptographic Integrity
Tests SHA-256 evidence hashing, tamper detection, and audit trail validity.
"""
import hashlib
import json
import pytest

def compute_evidence_hash(payload: dict) -> str:
    serialized = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def test_evidence_hashing_consistency():
    evidence = {
        "pcap_file": "attack_capture_2026.pcap",
        "packet_count": 48291,
        "source_ip": "192.168.56.104",
        "attack_detected": "DDoS SYN Flood"
    }
    hash1 = compute_evidence_hash(evidence)
    hash2 = compute_evidence_hash(evidence)
    assert hash1 == hash2
    assert len(hash1) == 64

def test_evidence_tamper_detection():
    original = {
        "source_ip": "192.168.56.104",
        "risk_score": 95.0
    }
    tampered = {
        "source_ip": "192.168.56.104",
        "risk_score": 10.0  # modified by malicious actor
    }
    assert compute_evidence_hash(original) != compute_evidence_hash(tampered)
