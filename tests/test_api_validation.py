"""
Test Suite 8: API Input Validation & Pydantic Schema Integrity
Tests validation error triggers when required parameters are missing or incorrect types are supplied.
"""
import pytest
from pydantic import ValidationError
from backend.routers.ioc import IOCSearchRequest, SaveIOCRequest
from backend.routers.incidents import CreateIncidentRequest, UpdateIncidentStatusRequest
from backend.routers.cases import CreateCaseRequest, AttachEvidenceRequest

def test_ioc_search_missing_field():
    with pytest.raises(ValidationError):
        IOCSearchRequest()  # missing required 'ioc'

def test_incident_create_missing_title():
    with pytest.raises(ValidationError):
        CreateIncidentRequest()  # missing required 'title'

def test_case_create_missing_title():
    with pytest.raises(ValidationError):
        CreateCaseRequest()  # missing required 'title'

def test_attach_evidence_missing_fields():
    with pytest.raises(ValidationError):
        AttachEvidenceRequest(evidence_type="IOC")  # missing required 'title'

def test_valid_schemas():
    assert IOCSearchRequest(ioc="8.8.8.8").ioc == "8.8.8.8"
    assert CreateIncidentRequest(title="Valid Title").title == "Valid Title"
    assert CreateCaseRequest(title="Valid Case").title == "Valid Case"
