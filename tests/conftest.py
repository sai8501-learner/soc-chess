"""
SOC Chess -- Shared Test Fixtures (conftest.py)
"""
import os
import sys
import json
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.config import settings
from backend.database import query, query_one, execute, init_db


@pytest.fixture(scope="session", autouse=True)
def ensure_db():
    try:
        init_db()
    except Exception as e:
        pytest.skip(f"Database unavailable: {e}")


@pytest.fixture
def sample_ioc_ip():
    return "192.168.56.104"


@pytest.fixture
def sample_ioc_domain():
    return "malware-test-domain.example.com"


@pytest.fixture
def sample_alert_id():
    rows = query("SELECT id FROM ai_alerts ORDER BY id DESC LIMIT 1;")
    return rows[0]["id"] if rows else None


@pytest.fixture
def sample_incident_id():
    rows = query("SELECT incident_id FROM incident_response ORDER BY id DESC LIMIT 1;")
    return rows[0]["incident_id"] if rows else None


@pytest.fixture
def sample_case_id():
    rows = query("SELECT case_id FROM soc_cases ORDER BY id DESC LIMIT 1;")
    return rows[0]["case_id"] if rows else None


@pytest.fixture
def sample_report_id():
    rows = query("SELECT report_id FROM reports ORDER BY id DESC LIMIT 1;")
    return rows[0]["report_id"] if rows else None
