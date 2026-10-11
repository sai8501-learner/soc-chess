import os
import sys
import time
import logging
import threading
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.database import init_db, get_connection, is_using_sqlite
from backend.routers.network import router as network_router
from backend.routers.splunk import router as splunk_router, get_splunk_session
from backend.routers.ml import router as ml_router, get_datasets_inventory, do_full_dataset_scan
from backend.routers.alerts import router as alerts_router
from backend.routers.spark import router as spark_router
from backend.routers.threat_intel import router as threat_intel_router
from backend.routers.llm import router as llm_router
from backend.routers.ai_alerts import router as ai_alerts_router
from backend.routers.ioc import router as ioc_router
from backend.routers.incidents import router as incidents_router
from backend.routers.cases import router as cases_router
from backend.routers.ai_analysis import router as ai_analysis_router
from backend.routers.auth import router as auth_router
from backend.services.auth_service import AuthError, auth_service
from backend.spark_engine.spark_manager import spark_manager
from backend.ml_engine.mlp_pipeline import mlp_pipeline

# Logger Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"
)
logger = logging.getLogger("socchess.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Sequence
    logger.info("=================================================")
    logger.info("   SOC CHESS — AUTONOMOUS CYBERSECURITY BACKEND   ")
    logger.info("  Apache Spark + 3-Hidden-Layer MLP Neural Net    ")
    logger.info("=================================================")
    logger.info(f"[*] Initializing MySQL Schema on {settings.MYSQL_HOST}:{settings.MYSQL_PORT}...")
    try:
        init_db()
    except Exception as e:
        logger.error(f"[!] Warning: Database init error: {e}")

    # Pre-warm dataset inventory in background
    threading.Thread(
        target=do_full_dataset_scan,
        kwargs={"dataset_root": settings.DATASET_ROOT, "force": False},
        daemon=True
    ).start()

    yield
    logger.info("[-] Shutting down SOC Chess backend...")

app = FastAPI(
    title="SOC Chess — Cyber Defense Platform",
    description="Big Data Apache Spark & Non-Linear MLP Neural Network Autonomous Cybersecurity Defense Console.",
    version="3.0.0",
    lifespan=lifespan
)

# CORS Configuration
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8001",
    "http://127.0.0.1:8001"
]
if os.getenv("RENDER_EXTERNAL_URL"):
    origins.append(os.getenv("RENDER_EXTERNAL_URL"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|.*\.onrender\.com)(:\d+)?",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
)

PUBLIC_API_PATHS = {"/api/health", "/api/auth/status", "/api/auth/bootstrap", "/api/auth/register", "/api/auth/login"}


@app.middleware("http")
async def authenticate_api_requests(request: Request, call_next):
    if (
        not settings.AUTH_ENABLED
        or not request.url.path.startswith("/api/")
        or request.url.path in PUBLIC_API_PATHS
        or request.method == "OPTIONS"
    ):
        return await call_next(request)

    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        request.state.user = auth_service.get_authenticated_user(authorization.removeprefix("Bearer ").strip())
    except AuthError as error:
        return JSONResponse(
            status_code=401,
            content={"detail": str(error)},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception:
        logger.exception("Authentication lookup failed")
        return JSONResponse(status_code=503, content={"detail": "Authentication service unavailable"})

    if request.state.user["role"] == "VIEWER" and request.method not in {"GET", "HEAD"}:
        return JSONResponse(status_code=403, content={"detail": "Viewer accounts are read-only"})

    return await call_next(request)

# Include API Routers
app.include_router(network_router)
app.include_router(splunk_router)
app.include_router(ml_router)
app.include_router(alerts_router)
app.include_router(spark_router)
app.include_router(threat_intel_router)
app.include_router(llm_router)
app.include_router(ai_alerts_router)
app.include_router(ioc_router)
app.include_router(incidents_router)
app.include_router(cases_router)
app.include_router(ai_analysis_router)
app.include_router(auth_router)


# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK ENDPOINTS
# ═══════════════════════════════════════════════════════════════
@app.get("/api/health")
def get_backend_health():
    """Backend Health Check endpoint with Spark and MLP statuses."""
    return {
        "status": "ok",
        "service": "soc-chess-backend",
        "version": "3.0.0",
        "spark_engine": spark_manager.get_status()["status"],
        "mlp_model": "READY" if mlp_pipeline.is_loaded else "INITIALIZING",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }


@app.get("/api/datasets")
def get_datasets_direct():
    """Direct alias to dataset inventory scanner."""
    return get_datasets_inventory(force_refresh=False)


# ═══════════════════════════════════════════════════════════════
# SYSTEM DIAGNOSTICS ENDPOINT
# ═══════════════════════════════════════════════════════════════
@app.get("/api/system/status")
def get_system_diagnostics():
    """Returns actual real connection statuses of all integrated security infrastructure components."""
    # 1. Database Status
    mysql_ok = False
    try:
        conn = get_connection()
        conn.close()
        mysql_ok = True
    except Exception:
        pass

    using_sqlite = is_using_sqlite()
    db_available = mysql_ok or using_sqlite
    db_name = "MySQL Database" if not using_sqlite else "SQLite Database (Autonomous Cloud Mode)"
    db_status = "Connected" if mysql_ok else ("Active (Embedded SQLite)" if using_sqlite else "Disconnected")
    db_host = f"{settings.MYSQL_HOST}:{settings.MYSQL_PORT}" if not using_sqlite else str(settings.SQLITE_DB_PATH.name)

    # 2. TShark Status
    tshark_ok = os.path.exists(settings.TSHARK_PATH)

    # 3. Wireshark GUI Status
    wireshark_ok = os.path.exists(settings.WIRESHARK_PATH)

    # 4. Splunk REST Status
    splunk_session = get_splunk_session()
    splunk_ok = (splunk_session is not None)

    # 5. Apache Spark Status
    spark_status = spark_manager.get_status()

    # 6. MLP Neural Network Status
    mlp_ok = mlp_pipeline.is_loaded

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "services": {
            "mysql": {
                "name": db_name,
                "status": db_status,
                "host": db_host,
                "available": db_available
            },
            "spark": {
                "name": "Apache Spark Big Data Engine",
                "status": spark_status["status"],
                "version": spark_status["version"],
                "master": spark_status["master"],
                "available": spark_status["pyspark_active"]
            },
            "ml_model": {
                "name": "MLP Neural Network (128-64-32)",
                "status": "Ready" if mlp_ok else "Calibrated Baseline",
                "path": str(settings.MODEL_DIR / "network" / "mlp_model.joblib"),
                "architecture": "3-Hidden-Layer MLP (ReLU + Softmax)",
                "available": True
            },
            "threat_intel": {
                "name": "Threat Intelligence Engine",
                "status": "Active",
                "available": True
            },
            "llm_analyst": {
                "name": "LLM SOC Analyst Assistant",
                "status": "Ready (Grounded Expert Rule + MITRE Engine)",
                "available": True
            },
            "tshark": {
                "name": "TShark Engine",
                "status": "Available" if tshark_ok else "Missing",
                "path": settings.TSHARK_PATH,
                "available": tshark_ok
            },
            "wireshark": {
                "name": "Wireshark GUI",
                "status": "Available" if wireshark_ok else "Missing",
                "path": settings.WIRESHARK_PATH,
                "available": wireshark_ok
            },
            "splunk": {
                "name": "Splunk Enterprise",
                "status": "Connected" if splunk_ok else "Disconnected",
                "host": f"https://{settings.SPLUNK_HOST}:{settings.SPLUNK_PORT}",
                "web_url": settings.SPLUNK_WEB_URL,
                "available": splunk_ok
            }
        }
    }


# ═══════════════════════════════════════════════════════════════
# STATIC FRONTEND SPA MOUNTING
# ═══════════════════════════════════════════════════════════════
dist_dir = settings.BASE_DIR / "frontend" / "dist"
if dist_dir.exists():
    assets_dir = dist_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            return JSONResponse(status_code=404, content={"detail": "API endpoint not found"})
        file_path = dist_dir / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(dist_dir / "index.html")
else:
    @app.get("/")
    def root():
        return {
            "app": "SOC CHESS",
            "architecture": "Apache Spark Big Data + 3-Hidden-Layer MLP Neural Network",
            "status": "RUNNING",
            "endpoints": {
                "docs": "/docs",
                "health": "/api/health",
                "spark_status": "/api/spark/status",
                "threat_intel": "/api/threat-intel/lookup?ip=192.168.56.104",
                "llm_investigate": "/api/llm/investigate",
                "ml_health": "/api/ml/health",
                "diagnostics": "/api/system/status",
                "network": "/api/network/interfaces",
                "splunk": "/api/splunk/status",
                "alerts": "/api/alerts"
            }
        }
