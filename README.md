# SOC CHESS — Real-Time Security Operations & AI Threat Detection Platform

SOC Chess is a local-first cybersecurity platform that integrates host packet capture (**Wireshark / TShark**), enterprise log correlation (**Splunk Enterprise REST API**), and threat classification (**scikit-learn MLP**) into a React, TypeScript, Tailwind CSS, and FastAPI command console.

---

## 1. System Architecture

For the complete, in-depth architectural specification, see **[SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md)**.

```
+-----------------------------------------------------------------------------------------------------+
|                                1. PRESENTATION LAYER (React 18 + TS)                                |
|   http://localhost:5173  |  Dark Theme Glassmorphism  |  Vite Bundler  |  Tailwind CSS               |
|                                                                                                     |
|  [Dashboard]      [Monitor]       [SIEM]        [AI Alerts]     [IOC Intel]    [SOAR IR]    [Cases] |
|   (/)             (/monitor)      (/siem)       (/ai-alerts)    (/ioc-intel)   (/incident)  (/cases)|
+--------+--------------+--------------+---------------+---------------+-------------+-----------+----+
         |              |              |               |               |             |           |
         | (HTTP REST)  | (WebSockets) | (SPL Link)    | (Report DL)   | (IOC Query) | (Playbook)|
         v              v              v               v               v             v           v
+------------------------------------------------------------------------------------------------+
|                        2. FASTAPI BACKEND GATEWAY (Python 3.10+ @ Port 8001)                   |
|   - CORS Middleware  - Async Uvicorn Worker  - Pydantic Validation  - Error Interceptors       |
|                                                                                                |
|  +--------------------+  +----------------------+  +---------------------+  +---------------+  |
|  | ai_alerts.py       |  | siem.py              |  | ioc.py & inc.py     |  | cases.py      |  |
|  | 12-Format Parsers  |  | Splunk REST Proxy    |  | Threat Feeds & SOAR |  | Case CRUD     |  |
|  +--------------------+  +----------------------+  +---------------------+  +---------------+  |
+-----------+--------------------------+-----------------------+----------------------+----------+
            |                          |                       |                      |
            | (Raw Telemetry)          | (REST API :8089)      | (IOC / Intel)        | (State)
            v                          v                       v                      v
+-----------------------+  +----------------------+  +--------------------+  +----------------+
| 3. INGESTION ENGINES  |  | SPLUNK ENTERPRISE    |  | IOC REGEX ENGINE   |  | WAMP64 MYSQL   |
| - Wireshark / TShark  |  | - Port 8089 (REST)   |  | - 8 Artifact Types |  | - Port 3306    |
| - 12 Log Parsers      |  | - Port 8000 (Web UI) |  | - IPs, URLs, C2    |  | - soc_cases    |
| - 3,708 Dataset Files |  | - CIM Data Models    |  | - Hashes, Files    |  | - alerts_db    |
+-----------+-----------+  +----------------------+  +---------+----------+  +----------------+
            |                                                  |
            v                                                  |
+---------------------------------------------------+          |
| 4. BIG DATA & CANONICAL FEATURE PIPELINE          |          |
| - Apache Spark 3.5.3 (PySpark Structured Stream)  |          |
| - 19 Canonical Flow & Security Event Features     |          |
| - StandardScaler Normalization + Log1p Smoothing  |          |
+---------------------------+-----------------------+          |
                            |                                  |
                            v                                  |
+---------------------------------------------------+          |
| 5. DUAL-TIER MACHINE LEARNING DETECTION ENGINE    |          |
|  - Tier 1: Real-Time 3-Layer MLP Neural Network   |          |
|    (128 -> 64 -> 32 ReLU + Softmax, <1.2ms)       |          |
|  - Tier 2: Random Forest (200 Trees) + XGBoost    |          |
|  - Continuous Risk Scoring (0 to 100 Scale)       |          |
|  - MITRE ATT&CK Matrix Mapping (T1110, T1059)     |          |
+---------------------------+-----------------------+          |
                            |                                  |
                            v                                  v
+---------------------------------------------------------------------------------------------+
| 6. HYBRID 4-TIER LLM GATEWAY & SOAR PLAYBOOK AUTOMATION                                     |
|  - Cascading Gateway: NVIDIA NIM (Llama-3.2) -> OpenAI (GPT-4o) -> Gemini -> Local Rule     |
|  - Dynamic Firewall Containment Script Synthesis (iptables, Windows netsh, net user)        |
|  - Automated 5-Stage SOC Investigation & Remediation Playbooks                              |
+---------------------------------------------------------------------------------------------+
                                             |
                                             v
+---------------------------------------------------------------------------------------------+
| 7. SERVER-SIDE EXPORT & REPORT GENERATION ENGINE                                            |
|    POST /api/ai-alerts/download-report -> StreamingResponse (Content-Disposition: attachment) |
|    Formats:  [PDF / Print HTML]   [DOC Word]   [TXT Raw]   [CSV Log]   [JSON Struct]        |
+---------------------------------------------------------------------------------------------+
```

---

## 2. Core Pages & Capabilities

### Page 1: Monitor (`/monitor`)
- **TShark & Wireshark Visibility**: Dynamically queries host network adapters via `tshark -D`.
- **Live Packet Capture**: Start and stop controlled packet capture on any host interface (e.g. `Ethernet 7`).
- **Real-Time Stream**: Live sub-second packet telemetry streamed directly to the React UI via WebSockets.
- **Protocol Metrics**: Real-time throughput rate (pkts/sec) and protocol breakdown pie chart (TCP, UDP, DNS, HTTP, TLS, ICMP).
- **Native Wireshark Launcher**: `[ OPEN WIRESHARK ]` triggers the host Wireshark executable via the `socchess://wireshark` protocol handler.

### Page 2: SIEM (`/siem`)
- **Splunk Enterprise REST Integration**: Directly authenticates with Splunk on `https://localhost:8089` using session token authentication.
- **Interactive SPL Search**: Execute real SPL searches (e.g. `search index=* | head 100`) with quick filter presets for Windows Event Codes (`4625`, `5156`, `4720`, `1102`).
- **Real KPI Dashboard**: Real-time counters for Total, Critical, High, Medium, and Low events, plus Top Event Hosts distribution.
- **Direct Splunk Web Link**: `[ OPEN SPLUNK ]` launches the actual Splunk Web UI on `http://localhost:8000`.

### Page 3: AI Alerts (`/ai-alerts`)
- **Dataset Manager**: Inspects files in `datasets/` (`combined_CICIDS2017_UNSWB15`, `CSE-CIC-IDS2018`, `MachineLearningCSV`, `UNSW-NB15_c`, `kddtest`), reporting row counts, columns, and target candidates.
- **Model Training Console**: Asynchronously trains the configured 3-layer `MLPClassifier` with balanced sample weights, leakage prevention, and standardized feature preprocessing.
- **Performance Verification**: Real evaluation metrics (Accuracy, Precision, Recall, F1 score, Confusion Matrix) saved to `ml/models/`.
- **Live Prediction Playground**: Interactive threat evaluator with automatic feature mapping and MITRE ATT&CK 5-stage Kill Chain visualizer.
- **AI Alerts Audit Trail**: Persists high-confidence threat detections to MySQL with source attribution tags (`NETWORK`, `SPLUNK`, `DATASET_TEST`, `MANUAL_TEST`).

### Additional Pages
- **AI Analysis** (`/ai-analysis`): attack anatomy and MITRE ATT&CK analysis.
- **IOC Intelligence** (`/ioc-intelligence`): indicator lookup and enrichment.
- **Incident Response** (`/incident-response`) and **SOC Cases** (`/soc-cases`): investigation workflows, evidence, and reports.

---

## 3. Installation & Setup

### Prerequisites
1. **Python 3.10+**
2. **Node.js 18+ & npm**
3. **MySQL (WAMP)** running on `localhost:3306`
4. **Wireshark & TShark** installed on `C:\Program Files\Wireshark\`
5. **Splunk Enterprise** running on `localhost:8000` (API: `8089`)
6. **A full JDK 17 or 21** for PySpark; Android Studio's bundled runtime is not supported.

### Step 1: Environment Configuration
Copy `.env.example` to `.env` (already configured):
```env
APP_NAME=SOC_CHESS
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8001
FRONTEND_PORT=5173
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_DATABASE=soc_chess
MYSQL_USERNAME=root
MYSQL_PASSWORD=
WIRESHARK_PATH=C:\Program Files\Wireshark\Wireshark.exe
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
SPLUNK_HOST=127.0.0.1
SPLUNK_PORT=8089
SPLUNK_WEB_URL=http://127.0.0.1:8000
SPLUNK_USERNAME=
SPLUNK_PASSWORD=
SPLUNK_INDEX=main
AUTH_ENABLED=true
JWT_SECRET=replace_with_a_unique_random_secret_of_at_least_32_characters
ACCESS_TOKEN_TTL_MINUTES=480
```

Use `.env.example` as the complete configuration reference. Set `JAVA_HOME`, `PYSPARK_PYTHON`, and `PYSPARK_DRIVER_PYTHON` before enabling Spark. Install pinned dependencies with:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
cd frontend
npm ci
```

### Step 2: Register Windows Wireshark Protocol
Run the batch file as Administrator:
```powershell
scripts\register_wireshark_protocol.bat
```

### Step 3: Start Application
Double click `start_soc_chess.bat` or start manually:

**Backend (FastAPI)**:
```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload
```

**Frontend (React Vite)**:
```powershell
cd frontend
npm run dev
```

Visit the dashboard at **`http://localhost:5173`**.

On the first visit, create the local administrator account in the setup screen. All API requests and packet-stream WebSockets require a signed access token after setup.

---

## 4. Security Controls
- **No Command Injection**: Controlled, validated parameters for TShark interface and packet limit.
- **Protected Secrets**: Credentials stored server-side in `.env` and never leaked to React clients.
- **Authenticated API**: Local bootstrap creates an administrator account; all API routes require a signed bearer token and viewer accounts are read-only.
- **Local Default Binding**: The launcher binds FastAPI to `127.0.0.1`, not the local network.
- **Safe Protocol Invocation**: `socchess://` protocol registers exclusively to `C:\Program Files\Wireshark\Wireshark.exe`.
- **Zero Mock / Fake Data**: All displays reflect verified data from local host processes, REST endpoints, and scikit-learn models.
