import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

endpoints = [
    ("GET", "/api/health"),
    ("GET", "/api/ml/health"),
    ("GET", "/api/ml/models"),
    ("GET", "/api/ml/inventory"),
    ("GET", "/api/spark/status"),
    ("GET", "/api/spark/stream/status"),
    ("GET", "/api/threat-intel/lookup?ip=192.168.56.104"),
    ("GET", "/api/alerts"),
    ("POST", "/api/spark/stream/start"),
    ("POST", "/api/spark/stream/stop"),
]

print("=" * 65)
print("FASTAPI BACKEND REST API HEALTH CHECK")
print("=" * 65)

all_passed = True
for method, ep in endpoints:
    try:
        if method == "GET":
            res = client.get(ep)
        else:
            res = client.post(ep)
        code = res.status_code
        status_text = "PASS" if code in [200, 201] else f"FAIL ({code})"
        if code not in [200, 201]:
            all_passed = False
        print(f"  [{code}] {method:<5} {ep:<45} -> {status_text}")
    except Exception as e:
        all_passed = False
        print(f"  [ERR] {method:<5} {ep:<45} -> EXCEPTION: {e}")

print("=" * 65)
if all_passed:
    print("  ALL API ENDPOINTS ARE 100% HEALTHY AND RESPONSIVE!")
else:
    print("  SOME API ENDPOINTS RETURNED NON-200 CODES")
print("=" * 65)
