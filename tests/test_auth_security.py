"""
Test Suite 7: API Defense & SQL Injection Prevention
Tests SQL injection resilience in query filters, parameter validation, and secure query mechanics.
"""
import pytest
from backend.routers.cases import list_cases
from backend.routers.incidents import list_incidents

def test_sql_injection_resilience_in_case_search():
    malicious_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE soc_cases; --",
        "1' UNION SELECT NULL, NULL, NULL--",
    ]
    for payload in malicious_payloads:
        res = list_cases(search=payload)
        assert "cases" in res
        assert isinstance(res["cases"], list)

def test_sql_injection_resilience_in_incident_search():
    malicious_payloads = [
        "' OR '1'='1",
        "admin'--",
        "1; WAITFOR DELAY '0:0:5'--"
    ]
    for payload in malicious_payloads:
        res = list_incidents(search=payload)
        assert "incidents" in res
        assert isinstance(res["incidents"], list)
