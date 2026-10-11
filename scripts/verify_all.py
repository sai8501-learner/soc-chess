import os
import sys
import time
import requests
import pymysql

print("=" * 70)
print("       SOC CHESS — COMPREHENSIVE END-TO-END SYSTEM AUDIT       ")
print("=" * 70)

BACKEND_URL = "http://127.0.0.1:8001"
all_passed = True

def check(step_name, func):
    global all_passed
    print(f"\n[*] Testing: {step_name}...")
    try:
        res = func()
        print(f"  [+] PASSED: {res}")
        return True
    except Exception as e:
        print(f"  [!] FAILED: {e}")
        all_passed = False
        return False

# 1. System Diagnostics
def test_diagnostics():
    r = requests.get(f"{BACKEND_URL}/api/system/status", timeout=5).json()
    services = r.get("services", {})
    statuses = {k: v.get("status") for k, v in services.items()}
    assert services.get("mysql", {}).get("available") == True, "MySQL not connected"
    assert services.get("splunk", {}).get("available") == True, "Splunk not connected"
    assert services.get("tshark", {}).get("available") == True, "TShark missing"
    assert services.get("wireshark", {}).get("available") == True, "Wireshark GUI missing"
    assert services.get("ml_model", {}).get("available") == True, "ML Model not ready"
    return f"All 5 Services Online -> {statuses}"

check("1. System Diagnostics (/api/system/status)", test_diagnostics)

# 2. Network Interfaces
def test_interfaces():
    r = requests.get(f"{BACKEND_URL}/api/network/interfaces", timeout=5).json()
    ifaces = r.get("interfaces", [])
    assert len(ifaces) > 0, "No interfaces detected"
    names = [i["name"] for i in ifaces[:3]]
    return f"Detected {len(ifaces)} interfaces (Sample: {names})"

check("2. Real TShark Interface Enumeration (/api/network/interfaces)", test_interfaces)

# 3. Splunk Status & Version
def test_splunk_status():
    r = requests.get(f"{BACKEND_URL}/api/splunk/status", timeout=5).json()
    assert r.get("status") == "connected", f"Splunk status: {r.get('status')}"
    return f"Connected to Splunk {r.get('version')} on host '{r.get('server_name')}' (Index: {r.get('index')})"

check("3. Splunk Enterprise REST Health (/api/splunk/status)", test_splunk_status)

# 4. Splunk SPL Search Execution
def test_splunk_search():
    r = requests.post(f"{BACKEND_URL}/api/splunk/search", json={
        "query": "search index=* | head 5",
        "max_results": 5
    }, timeout=10).json()
    events = r.get("events", [])
    assert r.get("status") == "success", "Search failed"
    return f"Retrieved {len(events)} live Splunk events in {r.get('execution_time_ms')}ms"

check("4. Real Splunk SPL Search Execution (/api/splunk/search)", test_splunk_search)

# 5. Splunk Dashboard Aggregates
def test_splunk_dashboard():
    r = requests.get(f"{BACKEND_URL}/api/splunk/dashboard", timeout=10).json()
    assert "total_events" in r, "Dashboard metrics missing"
    return f"Total: {r.get('total_events')} | Critical: {r.get('critical_events')} | High: {r.get('high_events')} | Low: {r.get('low_events')}"

check("5. Splunk SIEM KPI Metrics (/api/splunk/dashboard)", test_splunk_dashboard)

# 6. ML Datasets Inspection
def test_ml_datasets():
    r = requests.get(f"{BACKEND_URL}/api/ml/datasets", timeout=5).json()
    datasets = r.get("datasets", [])
    assert len(datasets) > 0, "No datasets detected in datasets/ directory"
    return f"Inventoried {len(datasets)} dataset files (Primary: {datasets[0].get('filename')})"

check("6. Dataset Manager & Inventory (/api/ml/datasets)", test_ml_datasets)

# 7. ML Threat Prediction
def test_ml_prediction():
    r = requests.post(f"{BACKEND_URL}/api/ml/predict", json={
        "features": {
            "src_port": 54145,
            "dst_port": 4444,
            "protocol": "TCP",
            "packet_len": 128,
            "flow_duration": 0.05
        },
        "source": "NETWORK"
    }, timeout=5).json()
    assert "prediction" in r and "risk_score" in r, "Invalid prediction structure"
    return f"Verdict: {r.get('prediction')} | Risk: {r.get('risk_score')}/100 | Severity: {r.get('severity')} | Action: {r.get('recommended_action')}"

check("7. Real Random Forest Threat Prediction (/api/ml/predict)", test_ml_prediction)

# 8. AI Threat Alerts Feed
def test_alerts_feed():
    r = requests.get(f"{BACKEND_URL}/api/alerts", timeout=5).json()
    alerts = r.get("alerts", [])
    return f"Persisted {len(alerts)} alerts in MySQL database"

check("8. AI Alerts MySQL Feed (/api/alerts)", test_alerts_feed)

# 9. Packet Capture Start & Stop Flow
def test_capture_lifecycle():
    # Start
    start_r = requests.post(f"{BACKEND_URL}/api/network/capture/start", json={
        "interface": "Ethernet 7",
        "packet_limit": 10
    }, timeout=5).json()
    time.sleep(2)
    # Status
    status_r = requests.get(f"{BACKEND_URL}/api/network/capture/status", timeout=5).json()
    # Stop
    stop_r = requests.post(f"{BACKEND_URL}/api/network/capture/stop", timeout=5).json()
    return f"Capture Session '{start_r.get('session_id')}' -> Started: {start_r.get('status')} -> Stopped: {stop_r.get('status')}"

check("9. TShark Live Capture Start & Stop (/api/network/capture/...)", test_capture_lifecycle)

# 10. Database Consistency
def test_database():
    conn = pymysql.connect(host="127.0.0.1", user="root", password="", database="soc_chess", charset="utf8mb4")
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES")
        tables = [list(r.values())[0] if isinstance(r, dict) else r[0] for r in cur.fetchall()]
        cur.execute("SELECT COUNT(*) FROM ai_alerts")
        alerts_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM splunk_queries")
        queries_count = cur.fetchone()[0]
    conn.close()
    return f"Verified {len(tables)} tables in MySQL 'soc_chess' (Alerts: {alerts_count}, Queries: {queries_count})"

check("10. MySQL Database Consistency & Relational Tables", test_database)

print("\n" + "=" * 70)
if all_passed:
    print(" >>> ALL 10 CORE COMPONENTS AND INFRASTRUCTURE CHECKS PASSED! <<<")
else:
    print(" >>> SOME CHECKS REPORTED ISSUES - REVIEW LOGS ABOVE <<<")
print("=" * 70)
