"""
SOC CHESS — High-Concurrency Performance & Load Testing Suite
Simulates 10+ concurrent security analysts querying backend endpoints,
running AI threat detections, searching IOCs, and managing incident cases.
Calculates throughput (RPS), error rates, and latency percentiles (p50, p90, p95, p99).
"""

import time
import json
import statistics
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.services.auth_service import auth_service

BASE_URL = "http://localhost:8001"

# Generate valid authentication token for simulated analyst sessions
AUTH_TOKEN = auth_service.create_access_token({"id": 1, "username": "load_test_analyst", "role": "ADMIN"})

# Sample Splunk SIEM Telemetry for live AI analysis load testing
SAMPLE_TELEMETRY = """
2026-09-28 01:00:01 EventCode=4625 ComputerName=DC-01.corp.internal User=Administrator Source_Network_Address=192.168.1.200 SubStatus=0xC000006A
2026-09-28 01:00:02 EventCode=4625 ComputerName=DC-01.corp.internal User=root Source_Network_Address=192.168.1.200 SubStatus=0xC000006A
2026-09-28 01:00:03 EventCode=4688 ComputerName=DC-01.corp.internal NewProcessName=powershell.exe CommandLine="powershell -enc aQBlAHgA"
""".strip()

WORKLOADS = [
    {
        "name": "Health & Diagnostics",
        "method": "GET",
        "endpoint": "/api/health",
        "data": None
    },
    {
        "name": "SOC Cases Query",
        "method": "GET",
        "endpoint": "/api/cases",
        "data": None
    },
    {
        "name": "Incident Registry",
        "method": "GET",
        "endpoint": "/api/incidents",
        "data": None
    },
    {
        "name": "IOC Threat Lookup",
        "method": "POST",
        "endpoint": "/api/ioc/search",
        "data": {"ioc": "185.220.101.5"}
    },
    {
        "name": "AI Threat Scanner (MLP + Rule)",
        "method": "POST",
        "endpoint": "/api/ai-alerts/analyze-raw",
        "data": {
            "format": "Splunk SIEM Events & Syslog",
            "raw_text": SAMPLE_TELEMETRY
        }
    }
]


def make_request(workload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{BASE_URL}{workload['endpoint']}"
    method = workload["method"]
    headers = {
        "Authorization": f"Bearer {AUTH_TOKEN}",
        "Accept": "application/json"
    }
    if workload["data"]:
        headers["Content-Type"] = "application/json"
        body = json.dumps(workload["data"]).encode("utf-8")
    else:
        body = None

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    start_time = time.perf_counter()
    status_code = 0
    success = False
    error_msg = ""

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            status_code = response.status
            response.read()
            if 200 <= status_code < 300:
                success = True
    except urllib.error.HTTPError as e:
        status_code = e.code
        error_msg = f"HTTP {e.code}"
    except Exception as e:
        error_msg = str(e)

    duration_ms = (time.perf_counter() - start_time) * 1000.0

    return {
        "name": workload["name"],
        "endpoint": workload["endpoint"],
        "status_code": status_code,
        "success": success,
        "duration_ms": duration_ms,
        "error": error_msg
    }


def simulate_user_session(user_id: int, requests_per_user: int = 5) -> List[Dict[str, Any]]:
    """Simulates a concurrent security analyst session executing various operational queries."""
    results: List[Dict[str, Any]] = []
    for i in range(requests_per_user):
        workload = WORKLOADS[i % len(WORKLOADS)]
        res = make_request(workload)
        res["user_id"] = user_id
        results.append(res)
        time.sleep(0.01)  # 10ms realistic network jitter
    return results


def run_load_test(concurrent_users: int = 12, requests_per_user: int = 6) -> Dict[str, Any]:
    total_expected = concurrent_users * requests_per_user
    print(f"\n{'='*75}")
    print(f"  SOC CHESS HIGH-CONCURRENCY PERFORMANCE & LOAD TEST SUITE")
    print(f"  Concurrent Active Users : {concurrent_users}")
    print(f"  Requests Per User       : {requests_per_user}")
    print(f"  Total Scheduled Requests: {total_expected}")
    print(f"  Target Server           : {BASE_URL}")
    print(f"{'='*75}\n")

    overall_start = time.perf_counter()
    all_results: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
        futures = [
            executor.submit(simulate_user_session, user_id=uid, requests_per_user=requests_per_user)
            for uid in range(1, concurrent_users + 1)
        ]
        for f in as_completed(futures):
            all_results.extend(f.result())

    total_time = time.perf_counter() - overall_start

    # Compute aggregate metrics
    total_requests = len(all_results)
    successful_requests = sum(1 for r in all_results if r["success"])
    failed_requests = total_requests - successful_requests
    error_rate = (failed_requests / total_requests) * 100.0 if total_requests else 0.0
    rps = total_requests / total_time if total_time > 0 else 0.0

    latencies = [r["duration_ms"] for r in all_results]
    latencies.sort()

    p50 = statistics.median(latencies) if latencies else 0.0
    p90 = latencies[int(len(latencies) * 0.90)] if latencies else 0.0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0.0
    mean_lat = statistics.mean(latencies) if latencies else 0.0
    min_lat = min(latencies) if latencies else 0.0
    max_lat = max(latencies) if latencies else 0.0

    # Per-workload metrics
    breakdown: Dict[str, Dict[str, Any]] = {}
    for w in WORKLOADS:
        w_name = w["name"]
        w_res = [r for r in all_results if r["name"] == w_name]
        w_lats = [r["duration_ms"] for r in w_res]
        w_succ = sum(1 for r in w_res if r["success"])
        breakdown[w_name] = {
            "count": len(w_res),
            "success": w_succ,
            "failed": len(w_res) - w_succ,
            "avg_ms": round(statistics.mean(w_lats), 2) if w_lats else 0.0,
            "p95_ms": round(w_lats[int(len(w_lats) * 0.95)], 2) if w_lats else 0.0,
        }

    report = {
        "concurrent_users": concurrent_users,
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "failed_requests": failed_requests,
        "error_rate_pct": round(error_rate, 2),
        "total_duration_sec": round(total_time, 2),
        "throughput_rps": round(rps, 2),
        "latency_min_ms": round(min_lat, 2),
        "latency_mean_ms": round(mean_lat, 2),
        "latency_p50_ms": round(p50, 2),
        "latency_p90_ms": round(p90, 2),
        "latency_p95_ms": round(p95, 2),
        "latency_p99_ms": round(p99, 2),
        "latency_max_ms": round(max_lat, 2),
        "breakdown": breakdown
    }

    # Print summary table to console
    print(f"--- Benchmark Results ({concurrent_users} Concurrent Users) ---")
    print(f"Total Requests      : {total_requests}")
    print(f"Successful Requests : {successful_requests} ({100.0 - error_rate:.1f}%)")
    print(f"Failed Requests     : {failed_requests} ({error_rate:.1f}%)")
    print(f"Throughput          : {rps:.2f} requests/second")
    print(f"Total Wall Clock    : {total_time:.2f} seconds")
    print(f"\n--- Latency Percentiles (ms) ---")
    print(f"  Min   : {min_lat:.2f} ms")
    print(f"  p50   : {p50:.2f} ms")
    print(f"  Mean  : {mean_lat:.2f} ms")
    print(f"  p90   : {p90:.2f} ms")
    print(f"  p95   : {p95:.2f} ms")
    print(f"  p99   : {p99:.2f} ms")
    print(f"  Max   : {max_lat:.2f} ms")

    print(f"\n--- Per-Endpoint Performance ---")
    for name, stats in breakdown.items():
        print(f"  [{name:<32}] Count: {stats['count']:>3} | Success: {stats['success']:>3} | Avg: {stats['avg_ms']:>6.2f} ms | p95: {stats['p95_ms']:>6.2f} ms")
    print(f"{'='*75}\n")

    return report


if __name__ == "__main__":
    # Execute load test with 12 concurrent users, 6 requests each = 72 requests
    res = run_load_test(concurrent_users=12, requests_per_user=6)
    
    with open("tests/load_test_results.json", "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print("[*] Benchmark results saved to tests/load_test_results.json")
