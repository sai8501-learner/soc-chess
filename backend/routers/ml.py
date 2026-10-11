import os
import sys
import time
import json
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File, Query
from pydantic import BaseModel

from backend.config import settings
from backend.spark_engine.spark_manager import spark_manager
from backend.spark_engine.spark_processor import spark_processor
from backend.ml_engine.dataset_detector import DatasetDetector, format_size_human
from backend.ml_engine.training_service import training_service
from backend.ml_engine.mlp_pipeline import mlp_pipeline
from backend.ml_engine.risk_engine import risk_engine
from backend.ml_engine.model_router import ModelRouter
from backend.services.threat_intel import threat_intel_service
from backend.services.llm_analyst import llm_analyst

router = APIRouter(prefix="/api/ml", tags=["Apache Spark & MLP Neural Network Engine"])


class MultiModalTrainRequest(BaseModel):
    mode: str = "all"  # 'all', 'network', 'windows_log'
    classification_mode: str = "multiclass"
    n_estimators: Optional[int] = 150
    max_samples_per_dataset: Optional[int] = 50000


# Cached inventory store for instantaneous API responses
_cached_inventory: Optional[Dict[str, Any]] = None
_cached_inventory_time: float = 0.0
CACHE_FILE = settings.MODEL_DIR / "inventory_cache.json"


def do_full_dataset_scan(dataset_root: Optional[Path] = None, force: bool = False) -> Dict[str, Any]:
    global _cached_inventory, _cached_inventory_time

    if not force:
        if _cached_inventory is not None:
            return _cached_inventory
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as fp:
                    _cached_inventory = json.load(fp)
                    _cached_inventory_time = time.time()
                    return _cached_inventory
            except Exception:
                pass

    root = dataset_root or settings.DATASET_ROOT
    if not root.exists():
        return {
            "status": "error",
            "root": str(root),
            "root_exists": False,
            "message": f"DATASET DIRECTORY NOT FOUND\nConfigured: {root}",
            "directories_scanned": 0,
            "files_scanned": 0,
            "supported_files": 0,
            "excluded_files": 0,
            "errors": [f"Directory {root} does not exist."],
            "total_discovered": 0,
            "supported_discovered": 0,
            "compatible_count": 0,
            "incompatible_count": 0,
            "excluded_zip_count": 0,
            "datasets": [],
            "excluded_files": [],
            "excluded_files_list": []
        }

    discovered = []
    excluded = []
    errors = []
    dirs_scanned = 0
    files_scanned = 0

    SUPPORTED_EXTS = {".csv", ".json", ".jsonl", ".parquet", ".pcap", ".pcapng", ".cap", ".zip", ".txt"}

    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath:
            continue
        dirs_scanned += 1

        for fname in filenames:
            if fname.startswith("."):
                continue

            ext = os.path.splitext(fname)[1].lower()
            if ext not in SUPPORTED_EXTS:
                continue

            file_path = Path(dirpath) / fname
            files_scanned += 1

            try:
                item = DatasetDetector.inspect_file(file_path, root)
                if item["format"] == "ZIP":
                    excluded.append(item)
                else:
                    discovered.append(item)
            except Exception as e:
                err_str = f"Error inspecting {fname}: {str(e)}"
                errors.append(err_str)

    discovered.sort(key=lambda x: (x.get("compatibility") != "Compatible", -x.get("size_mb", 0)))
    compatible_count = sum(1 for d in discovered if d.get("compatibility") == "Compatible")
    incompatible_count = len(discovered) - compatible_count

    res = {
        "status": "ok",
        "root": str(root),
        "root_exists": True,
        "directories_scanned": dirs_scanned,
        "files_scanned": files_scanned,
        "supported_files": len(discovered),
        "excluded_files": len(excluded),
        "errors": errors,
        "total_discovered": len(discovered) + len(excluded),
        "supported_discovered": len(discovered),
        "compatible_count": compatible_count,
        "incompatible_count": incompatible_count,
        "excluded_zip_count": len(excluded),
        "datasets": discovered,
        "excluded_files": excluded,
        "excluded_files_list": excluded
    }
    _cached_inventory = res
    _cached_inventory_time = time.time()
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as fp:
            json.dump(res, fp)
    except Exception:
        pass
    return res


# ═══════════════════════════════════════════════════════════════
# 1. HEALTH & METRICS
# ═══════════════════════════════════════════════════════════════
@router.get("/health")
def get_ml_health():
    dataset_root = settings.DATASET_ROOT
    root_exists = dataset_root.exists()

    mlp_model_p = settings.MODEL_DIR / "network" / "mlp_model.joblib"
    root_model_p = settings.MODEL_DIR / "model.joblib"
    mlp_model_avail = mlp_model_p.exists() or root_model_p.exists() or mlp_pipeline.is_loaded

    tshark_path = getattr(settings, "TSHARK_PATH", r"C:\Program Files\Wireshark\tshark.exe")
    tshark_avail = Path(tshark_path).exists() if tshark_path else False

    ds_count = _cached_inventory.get("total_discovered", 0) if _cached_inventory else (1 if root_exists else 0)

    return {
        "status": "ok",
        "service": "soc-chess-spark-mlp-engine",
        "python_version": sys.version.split()[0],
        "model_architecture": "3-Hidden-Layer Multi-Layer Perceptron (MLP) Neural Network",
        "hidden_layers": [128, 64, 32],
        "activation": "ReLU",
        "output_layer": "Softmax",
        "spark_layer": "Apache Spark Big Data Processing Layer",
        "spark_status": spark_manager.get_status()["status"],
        "dataset_root": str(dataset_root),
        "dataset_root_exists": root_exists,
        "dataset_count": ds_count,
        "model_available": mlp_model_avail,
        "mlp_model_available": mlp_model_avail,
        "tshark": {"available": tshark_avail}
    }


# ═══════════════════════════════════════════════════════════════
# 2. DATASET DISCOVERY & FINGERPRINT INVENTORY
# ═══════════════════════════════════════════════════════════════
@router.get("/datasets")
@router.get("/inventory")
def get_datasets_inventory(force_refresh: bool = False):
    return do_full_dataset_scan(settings.DATASET_ROOT, force=force_refresh)


@router.get("/datasets/inspect")
def inspect_dataset_item(path: str = Query(..., description="Relative path of the dataset")):
    dataset_root = settings.DATASET_ROOT
    target_path = (dataset_root / path).resolve()

    if not str(target_path).startswith(str(dataset_root.resolve())):
        raise HTTPException(status_code=400, detail="Invalid path traversal attempt.")

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail=f"Dataset file not found: {path}")

    return DatasetDetector.inspect_dataset_detail(target_path, dataset_root)


# ═══════════════════════════════════════════════════════════════
# 3. SPARK + MLP NEURAL NETWORK TRAINING
# ═══════════════════════════════════════════════════════════════
@router.post("/train")
@router.post("/train/all")
def train_mlp_model(req: MultiModalTrainRequest, background_tasks: BackgroundTasks):
    with training_service.lock:
        if training_service.status in ["Running", "Queued"]:
            raise HTTPException(status_code=409, detail="A model training job is already in progress.")

        job_id = f"job-{int(time.time())}"
        training_service.reset(job_id)

        background_tasks.add_task(
            training_service.execute_training_job,
            req.mode,
            req.classification_mode,
            req.n_estimators or 150,
            req.max_samples_per_dataset or 50000
        )

        return {
            "job_id": job_id,
            "status": "queued",
            "architecture": "3-Hidden-Layer MLP Neural Network (128-64-32 ReLU)",
            "message": f"Apache Spark + MLP Neural Network training job '{job_id}' queued in background."
        }


@router.post("/train/network")
def train_network_only(background_tasks: BackgroundTasks):
    return train_mlp_model(MultiModalTrainRequest(mode="network"), background_tasks)


@router.post("/train/windows-log")
def train_windows_log_only(background_tasks: BackgroundTasks):
    return train_mlp_model(MultiModalTrainRequest(mode="windows_log"), background_tasks)


@router.get("/training-status/{job_id}")
@router.get("/train/status")
def get_training_status(job_id: Optional[str] = None):
    duration = 0.0
    if training_service.start_time:
        end = training_service.end_time or time.time()
        duration = round(end - training_service.start_time, 2)

    return {
        "job_id": training_service.job_id,
        "status": training_service.status,
        "stage": training_service.current_stage,
        "progress_percentage": training_service.progress_percentage,
        "progress_message": training_service.progress_message,
        "duration_seconds": duration,
        "logs": training_service.logs,
        "network_metrics": training_service.network_metrics,
        "log_metrics": training_service.log_metrics,
        "error": training_service.error
    }


# ═══════════════════════════════════════════════════════════════
# 4. MODEL REGISTRY
# ═══════════════════════════════════════════════════════════════
@router.get("/models")
def list_models():
    models_list = []
    net_dir = settings.MODEL_DIR / "network"
    if net_dir.exists():
        for metrics_f in sorted(net_dir.glob("**/metrics.json"), reverse=True):
            try:
                with open(metrics_f, "r", encoding="utf-8") as fp:
                    meta = json.load(fp)
                    models_list.append(meta)
            except Exception:
                pass

    if not models_list and mlp_pipeline.metadata:
        models_list.append(mlp_pipeline.metadata)

    return {
        "models": models_list,
        "network_models": models_list,
        "windows_log_models": []
    }


# ═══════════════════════════════════════════════════════════════
# 5. SPARK BIG DATA INFERENCE & MULTI-FORMAT TESTING
# ═══════════════════════════════════════════════════════════════
@router.post("/test-file")
@router.post("/analyze-file")
@router.post("/upload")
async def analyze_uploaded_file(file: UploadFile = File(...)):
    filename = file.filename or "uploaded_dataset"
    upload_dir = settings.BASE_DIR / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    temp_path = upload_dir / f"test_{int(time.time())}_{filename}"

    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        res = ModelRouter.route_and_evaluate_file(temp_path, filename)
        return res
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


@router.post("/analyze-sample")
def analyze_sample_file(sample_path: str = Query(...)):
    file_path = (settings.DATASET_ROOT / sample_path).resolve()
    if not file_path.exists():
        file_path = (settings.BASE_DIR / sample_path).resolve()
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Sample file '{sample_path}' not found.")

    try:
        return ModelRouter.route_and_evaluate_file(file_path, file_path.name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Spark + MLP inference failed on {file_path.name}: {str(e)}")


@router.get("/sample-files")
def list_sample_files():
    samples = []
    d_dir = settings.DATASET_ROOT
    if d_dir.exists():
        SUPPORTED_EXTS = {".csv", ".txt", ".json", ".pcap", ".pcapng"}
        for dirpath, dirnames, filenames in os.walk(d_dir):
            if ".git" in dirpath:
                continue
            for fname in filenames:
                if fname.startswith("."):
                    continue
                ext = os.path.splitext(fname)[1].lower()
                if ext in SUPPORTED_EXTS:
                    p = Path(dirpath) / fname
                    rel = str(p.relative_to(d_dir)).replace("\\", "/")
                    fmt = DatasetDetector.detect_format(p)
                    samples.append({
                        "name": fname,
                        "path": rel,
                        "type": f"{fmt} Dataset",
                        "size_kb": round(p.stat().st_size / 1024, 1)
                    })
                    if len(samples) >= 40:
                        break
            if len(samples) >= 40:
                break
    return {"samples": samples}


# ═══════════════════════════════════════════════════════════════
# 6. MLP PREDICTION, RISK SCORING & LLM EXPLAINABILITY
# ═══════════════════════════════════════════════════════════════
@router.post("/predict")
def predict_threat(payload: Dict[str, Any]):
    """
    Evaluates network/security features through MLP Neural Network -> Risk Engine -> Threat Intel -> LLM.
    """
    features = payload.get("features", payload)
    src_ip = features.get("src_ip") or features.get("source_ip") or "192.168.56.104"
    dst_ip = features.get("dst_ip") or features.get("destination_ip") or "192.168.56.107"

    # 1. Spark Feature Extraction for single packet/flow
    _, feat_vector = spark_processor.process_single_packet(features)

    # 2. MLP Neural Network Inference
    pred = mlp_pipeline.predict(feat_vector)
    attack_type = pred["attack_type"]
    confidence = pred["confidence"]
    is_attack = pred["is_attack"]

    # 3. Threat Intelligence Enrichment
    ti_res = threat_intel_service.lookup_ip(src_ip)
    ti_score = float(ti_res.get("threat_score", 0))

    # 4. Risk Score Engine
    risk_res = risk_engine.calculate_risk(
        attack_type=attack_type,
        mlp_confidence=confidence,
        is_attack=is_attack,
        threat_intel_score=ti_score,
        destination_ip=dst_ip
    )

    # 5. LLM SOC Analyst Assistant Report
    llm_report = llm_analyst.generate_investigation_report({
        "attack_type": attack_type,
        "mlp_confidence": confidence,
        "risk_score": risk_res["risk_score"],
        "risk_status": risk_res["risk_status"],
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "threat_intel": ti_res
    })

    return {
        "prediction": attack_type,
        "attack_type": attack_type,
        "confidence": confidence,
        "mlp_confidence": confidence,
        "risk_score": risk_res["risk_score"],
        "risk_status": risk_res["risk_status"],
        "severity": risk_res["risk_status"],
        "is_attack": is_attack,
        "classification": "Attack" if is_attack else "Normal",
        "threat_intel": ti_res,
        "risk_evidence": risk_res["evidence"],
        "llm_report": llm_report,
        "recommended_action": llm_report.get("recommended_action", "Monitor flow"),
        "model_architecture": "3-Hidden-Layer MLP Neural Network (128-64-32 ReLU)"
    }


@router.post("/analyze-packet-enhanced")
def analyze_packet_enhanced(packet: Dict[str, Any]):
    """
    Enhanced deep inspection of a single network packet through the complete SOC pipeline:
    Spark Cleaning -> MLP Neural Network -> Threat Intel -> Risk Engine -> LLM Analyst.
    """
    dst_p = int(packet.get("dst_port") or packet.get("destination_port", 80))
    src_p = int(packet.get("src_port") or packet.get("source_port", 50000))
    src_ip = str(packet.get("src_ip") or packet.get("source_ip", "192.168.56.104"))
    dst_ip = str(packet.get("dst_ip") or packet.get("destination_ip", "192.168.56.107"))
    proto = str(packet.get("protocol", "TCP")).upper()

    # 1. Spark Feature Extraction
    feat_dict, feat_vector = spark_processor.process_single_packet(packet)

    # 2. MLP Neural Network Classification
    pred = mlp_pipeline.predict(feat_vector)
    label = pred["attack_type"]
    conf = pred["confidence"]
    is_attack = pred["is_attack"]

    # 3. Threat Intelligence Enrichment
    ti_res = threat_intel_service.lookup_ip(src_ip)
    ti_score = float(ti_res.get("threat_score", 0))

    # 4. Risk Score Engine
    risk_res = risk_engine.calculate_risk(
        attack_type=label,
        mlp_confidence=conf,
        is_attack=is_attack,
        threat_intel_score=ti_score,
        destination_ip=dst_ip
    )
    risk = risk_res["risk_score"]
    sev = risk_res["risk_status"]

    # 5. LLM SOC Analyst Assistant Report
    llm_report = llm_analyst.generate_investigation_report({
        "attack_type": label,
        "mlp_confidence": conf,
        "risk_score": risk,
        "risk_status": sev,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_p,
        "destination_port": dst_p,
        "protocol": proto,
        "threat_intel": ti_res
    })

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "alert_status": sev if is_attack else "NORMAL",
        "is_attack": is_attack,
        "attack_category": label if is_attack else "Normal Traffic",
        "prediction": label,
        "confidence": conf,
        "mlp_confidence": conf,
        "risk_score": risk,
        "risk_status": sev,
        "severity_score": risk,
        "threat_level": sev,
        "source_ip": src_ip,
        "source_device": f"Host ({src_ip})",
        "destination_ip": dst_ip,
        "destination_device": f"Target ({dst_ip})",
        "protocol_details": {
            "protocol": proto,
            "src_port": src_p,
            "dst_port": dst_p,
            "flags": packet.get("flags", "")
        },
        "threat_intel": ti_res,
        "mitre_technique": llm_report.get("mitre_technique", "T1046 - Network Service Scanning"),
        "llm_report": llm_report,
        "recommendation": llm_report.get("recommended_action", "Isolate host and block port"),
        "explanation": f"MLP Neural Network classified as {label} with {conf:.1f}% confidence. Risk Score: {risk}/100 ({sev}).",
        "raw_attributes": packet
    }
