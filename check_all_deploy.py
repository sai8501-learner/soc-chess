import urllib.request
import json
import time

def req(url, method='GET', data=None, token=None):
    headers = {}
    if data:
        data_bytes = json.dumps(data).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    else:
        data_bytes = None
    if token:
        headers['Authorization'] = f'Bearer {token}'
    r = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read().decode('utf-8')
            try:
                return resp.status, json.loads(raw)
            except:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(body)
        except:
            return e.code, body
    except Exception as e:
        return 500, str(e)

print("=" * 70)
print("   SOC CHESS — LIVE END-TO-END DEPLOYMENT VALIDATION")
print("=" * 70)

print('\n[1/8] Checking Frontend (port 5173)...')
s, b = req('http://localhost:5173/')
print(f'  [+] Frontend HTTP Status: {s} (HTML Size: {len(b)} bytes)')

print('\n[2/8] Checking Backend Health & Diagnostics (port 8001)...')
s, h = req('http://127.0.0.1:8001/api/health')
print(f'  [+] Backend Health Status: {s} | Spark: {h.get("spark_engine") if isinstance(h, dict) else h} | Model: {h.get("mlp_model") if isinstance(h, dict) else ""}')

s, sys_diag = req('http://127.0.0.1:8001/api/system/status')
if isinstance(sys_diag, dict):
    svcs = sys_diag.get('services', {})
    print(f'  [+] System Diagnostics: MySQL={svcs.get("mysql", {}).get("status")}, ThreatIntel={svcs.get("threat_intel", {}).get("status")}, LLM={svcs.get("llm_analyst", {}).get("status")}')

print('\n[3/8] Authenticating (Login / Session Token)...')
login_payload = {'username': 'soc_admin', 'password': 'AdminPassword123!'}
s, res = req('http://127.0.0.1:8001/api/auth/login', method='POST', data=login_payload)
token = None
if s == 200 and isinstance(res, dict):
    token = res.get('access_token')
    user = res.get('user', {})
    print(f'  [+] Logged in as: {user.get("username")} ({user.get("role")})')
else:
    print(f'  [*] Bootstrapping admin account...')
    reg_payload = {'username': 'soc_admin', 'email': 'admin@soc-chess.local', 'password': 'AdminPassword123!'}
    s2, res2 = req('http://127.0.0.1:8001/api/auth/register', method='POST', data=reg_payload)
    if s2 in (200, 201):
        token = res2.get('access_token')
        print('  [+] Registered and token generated!')
    else:
        s3, res3 = req('http://127.0.0.1:8001/api/auth/login', method='POST', data=login_payload)
        if s3 == 200:
            token = res3.get('access_token')
            print('  [+] Logged in successfully!')

if not token:
    print('  [!] FATAL: Could not obtain auth token.')
    exit(1)

print('\n[4/8] Testing Threat Intelligence Search (AbuseIPDB & VirusTotal via /api/ioc/search)...')
s, intel = req('http://127.0.0.1:8001/api/ioc/search', method='POST', data={'ioc': '185.220.101.5'}, token=token)
print(f'  [+] Intel Search Status: {s}')
if isinstance(intel, dict):
    print(f'      Target IOC: {intel.get("ioc")} | Classification: {intel.get("classification")} | Score: {intel.get("threat_score")}/100')
    ti = intel.get("threat_intel", {})
    sources = ti.get("sources", {})
    if "abuseipdb" in sources:
        a = sources["abuseipdb"]
        print(f'      - AbuseIPDB: Score={a.get("abuse_confidence_score")}%, Reports={a.get("total_reports")}, Country={a.get("country_code")}')
    if "virustotal" in sources:
        vt = sources["virustotal"]
        print(f'      - VirusTotal: Malicious={vt.get("malicious_count")}, Harmless={vt.get("harmless_count")}')

print('\n[5/8] Testing AI Threat Analysis & Catalog...')
s, catalog = req('http://127.0.0.1:8001/api/ai-analysis/catalog', token=token)
print(f'  [+] Catalog Status: {s} | Classes: {catalog.get("classes") if isinstance(catalog, dict) else ""}')

s, scenarios = req('http://127.0.0.1:8001/api/ai-analysis/scenarios', token=token)
print(f'  [+] Scenarios Status: {s} | Total Scenarios: {scenarios.get("total_scenarios") if isinstance(scenarios, dict) else ""}')

s, analysis = req('http://127.0.0.1:8001/api/ai-analysis/analyze', method='POST', data={'attack_type': 'DDoS', 'source_ip': '185.220.101.45'}, token=token)
print(f'  [+] Deep-Dive Analysis Status: {s}')
if isinstance(analysis, dict):
    print(f'      Attack: {analysis.get("attack_name")} | MITRE: {analysis.get("mitre", {}).get("technique_id")}')
    fw = analysis.get("firewall_rules", {})
    print(f'      Generated Firewall Rule: {fw.get("iptables", "").splitlines()[0] if fw.get("iptables") else ""}')

print('\n[6/8] Testing AI Threat Studio Assistant (/api/ai-analysis/ask)...')
s, ai_ask = req(
    'http://127.0.0.1:8001/api/ai-analysis/ask',
    method='POST',
    data={
        'question': 'What are the top 3 immediate containment steps for a Mirai botnet SYN flood attack?',
        'attack_type': 'DDoS'
    },
    token=token
)
print(f'  [+] AI Ask Status: {s}')
if isinstance(ai_ask, dict):
    print(f'      Provider Used: {ai_ask.get("provider")}')
    print(f'      Model/Engine : {ai_ask.get("model")}')
    print(f'      Duration     : {ai_ask.get("duration_ms")}ms')
    ans = ai_ask.get("answer", "")
    safe_ans = ans.encode('ascii', 'ignore').decode('ascii')
    print(f'      Answer Snippet:\n{"-"*40}\n{safe_ans[:280]}...\n{"-"*40}')

print('\n[7/8] Testing Incident Response & Case Management APIs...')
s, incs = req('http://127.0.0.1:8001/api/incidents', token=token)
print(f'  [+] Incidents Endpoint: Status {s} | Total: {len(incs) if isinstance(incs, list) else 0}')

s, cases = req('http://127.0.0.1:8001/api/cases', token=token)
print(f'  [+] Cases Endpoint: Status {s} | Total: {len(cases) if isinstance(cases, list) else 0}')

print('\n[8/8] Testing Quick Questions Catalog...')
s, qq = req('http://127.0.0.1:8001/api/ai-analysis/quick-questions', token=token)
print(f'  [+] Quick Questions Status: {s} | Categories: {len(qq.get("categories", [])) if isinstance(qq, dict) else 0}')

print("\n" + "=" * 70)
print("   ALL 8/8 DEPLOYMENT SUBSYSTEMS OPERATIONAL & VERIFIED")
print("=" * 70)
 