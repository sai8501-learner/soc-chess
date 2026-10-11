import os
import time
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

import numpy as np
import pandas as pd
from backend.spark_engine.spark_manager import spark_manager
from backend.spark_engine.spark_processor import spark_processor
from backend.ml_engine.mlp_pipeline import mlp_pipeline
from backend.ml_engine.risk_engine import risk_engine
from backend.services.threat_intel import threat_intel_service
from backend.services.llm_analyst import llm_analyst
from backend.ml_engine.dataset_detector import DatasetDetector, UNSW_OFFICIAL_COLS, KDD_OFFICIAL_COLS
from backend.ml_engine.pcap_pipeline import PCAPPipeline

logger = logging.getLogger("socchess.ml.model_router")


def sanitize_for_json(obj: Any) -> Any:
    """Recursively converts numpy and pandas types to standard python primitives."""
    if isinstance(obj, dict):
        return {str(k): sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [sanitize_for_json(item) for item in obj]
    elif isinstance(obj, np.ndarray):
        return [sanitize_for_json(item) for item in obj.tolist()]
    elif isinstance(obj, (np.bool_, bool)):
        return bool(obj)
    elif isinstance(obj, (np.integer, int)):
        return int(obj)
    elif isinstance(obj, (np.floating, float)):
        return 0.0 if (np.isnan(obj) or np.isinf(obj)) else float(obj)
    elif pd.isna(obj):
        return None
    elif hasattr(obj, "item"):
        return sanitize_for_json(obj.item())
    elif isinstance(obj, Path):
        return str(obj)
    return obj


class ModelRouter:
    """
    Intelligent Spark + MLP Model Router:
    Inspects input content, performs Spark Big Data feature extraction,
    runs 3-Hidden-Layer MLP neural network inference, Risk Scoring, Threat Intel, and LLM explanation.
    """

    @classmethod
    def route_and_evaluate_file(
        cls,
        file_path: Path,
        filename: str,
        network_model_dir: Optional[Path] = None,
        log_model_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        raw_res = cls._evaluate_internal(file_path, filename)
        return sanitize_for_json(raw_res)

    @classmethod
    def _evaluate_internal(cls, file_path: Path, filename: str) -> Dict[str, Any]:
        fmt = DatasetDetector.detect_format(file_path)

        # 1. PCAP / PCAPNG Routing
        if fmt in ["PCAP", "PCAPNG"]:
            res = PCAPPipeline.process_and_evaluate(file_path, filename, None)
            res["detected_format"] = fmt
            res["detected_modality"] = "NETWORK_PACKET_CAPTURE"
            res["routed_pipeline"] = "Spark PCAP Stream Extractor -> MLP Neural Network"
            res["routed_model"] = "MLP 3-Hidden-Layer Classifier (128-64-32)"
            return res

        # 2. Ingest Dataset with Apache Spark
        df = spark_manager.load_dataset_spark(file_path, max_rows=500)
        if df is None or len(df) == 0:
            return {
                "filename": filename,
                "detected_format": fmt,
                "detected_modality": "UNKNOWN",
                "status": "ERROR",
                "message": "Failed to parse file schema.",
                "total_records": 0,
                "results": [],
                "summary": {"normal": 0, "suspicious": 0, "attack": 0, "critical": 0, "avg_risk_score": 0.0, "avg_confidence": 0.0, "top_sources": []}
            }

        cols = [str(c).strip() for c in df.columns]
        modality, family = DatasetDetector._classify_columns(cols, sample_df=df)

        is_log = "LOG" in modality
        if is_log:
            _, feature_matrix, _, raw_records = spark_processor.process_splunk_logs_dataframe(df)
            pipeline_name = "Spark Splunk/Windows Log Processor"
        else:
            _, feature_matrix, _ = spark_processor.process_network_dataframe(df)
            raw_records = []
            pipeline_name = "Spark Network Flow Engine"

        # 3. Multi-Layer Perceptron (MLP) High-Performance Vector Batch Evaluation
        preds = mlp_pipeline.predict_batch(feature_matrix)
        results = []
        normal_cnt = 0
        suspicious_cnt = 0
        attack_cnt = 0
        critical_cnt = 0
        total_risk = 0.0
        total_conf = 0.0
        src_counts = {}
        ti_cache = {}

        for idx in range(len(df)):
            row_dict = df.iloc[idx].to_dict()
            pred = preds[idx] if idx < len(preds) else mlp_pipeline.predict(feature_matrix[idx])
            label = pred["attack_type"]
            conf = pred["confidence"]
            is_att = pred["is_attack"]

            def _safe_int(val: Any, default: int = 0) -> int:
                if val is None or pd.isna(val):
                    return default
                try:
                    return int(float(val))
                except Exception:
                    return default

            # Extract source/dest details
            if is_log:
                src_ip = str(row_dict.get("ComputerName") or row_dict.get("host") or row_dict.get("src_ip") or "WIN-VICTIM10")
                dst_ip = str(row_dict.get("Account_Name") or row_dict.get("User") or "SYSTEM")
                src_p = _safe_int(row_dict.get("EventCode"), 4624)
                dst_p = 0
                proto = "LOG"
            else:
                src_ip = str(row_dict.get("src_ip") or row_dict.get("source_ip") or row_dict.get("srcip") or "192.168.56.104")
                dst_ip = str(row_dict.get("dst_ip") or row_dict.get("destination_ip") or row_dict.get("dstip") or "192.168.56.107")
                src_p = _safe_int(row_dict.get("src_port") or row_dict.get("source_port") or row_dict.get("sport"), 50000)
                dst_p = _safe_int(row_dict.get("dst_port") or row_dict.get("destination_port") or row_dict.get("dsport"), 80)
                proto = str(row_dict.get("protocol") or row_dict.get("proto") or "TCP").upper()

            # Threat Intelligence Lookup with local batch cache
            if src_ip not in ti_cache:
                ti_cache[src_ip] = threat_intel_service.lookup_ip(src_ip)
            ti_res = ti_cache[src_ip]
            ti_score = float(ti_res.get("threat_score", 0))

            # Risk Score Engine
            risk_calc = risk_engine.calculate_risk(
                attack_type=label,
                mlp_confidence=conf,
                is_attack=is_att,
                threat_intel_score=ti_score,
                event_frequency=src_counts.get(src_ip, 1),
                destination_ip=dst_ip
            )
            risk_val = risk_calc["risk_score"]
            risk_stat = risk_calc["risk_status"]

            # Count statuses
            if risk_stat == "CRITICAL":
                critical_cnt += 1
            elif risk_stat == "HIGH" or is_att:
                attack_cnt += 1
            elif risk_stat == "MEDIUM":
                suspicious_cnt += 1
            else:
                normal_cnt += 1

            total_risk += risk_val
            total_conf += conf
            src_counts[src_ip] = src_counts.get(src_ip, 0) + 1

            # Build Enhanced Result with LLM investigation
            mitre_str = "T1046 - Network Service Scanning" if is_att else "N/A"
            if label == "DDoS": mitre_str = "T1498 - Network Denial of Service"
            elif label == "Brute Force": mitre_str = "T1110 - Brute Force"
            elif label == "Infiltration": mitre_str = "T1059 - Command and Scripting Interpreter"

            enhanced_item = {
                "timestamp": str(row_dict.get("timestamp") or row_dict.get("_time") or row_dict.get("Time") or time.strftime("%Y-%m-%d %H:%M:%S")),
                "alert_status": risk_stat if is_att else "NORMAL",
                "is_attack": is_att,
                "attack_category": label,
                "prediction": label,
                "confidence": conf,
                "mlp_confidence": conf,
                "risk_score": risk_val,
                "severity_score": risk_val,
                "threat_level": risk_stat,
                "source_ip": src_ip,
                "source_device": f"Host ({src_ip})",
                "destination_ip": dst_ip,
                "destination_device": f"Target ({dst_ip})",
                "protocol_details": {
                    "protocol": proto,
                    "src_port": src_p,
                    "dst_port": dst_p,
                    "flags": str(row_dict.get("flags") or "")
                },
                "mitre_technique": mitre_str,
                "threat_intel": ti_res,
                "risk_evidence": risk_calc["evidence"],
                "recommendation": "Isolate source host and enforce firewall rules" if is_att else "Maintain standard operational monitoring",
                "explanation": f"MLP Neural Network classified as {label} with {conf:.1f}% confidence. Risk Score: {risk_val}/100 ({risk_stat}).",
                "raw_attributes": row_dict
            }
            results.append(enhanced_item)

        avg_risk = round(total_risk / max(1, len(df)), 1)
        avg_conf = round(total_conf / max(1, len(df)), 1)
        top_src = [{"source_ip": ip, "device": f"Host ({ip})", "count": count} for ip, count in sorted(src_counts.items(), key=lambda x: -x[1])[:5]]

        return {
            "filename": filename,
            "detected_format": fmt,
            "detected_modality": modality,
            "dataset_family": family,
            "routed_pipeline": f"{pipeline_name} -> 3-Hidden-Layer MLP Neural Network",
            "routed_model": "MLPClassifier (128-64-32 ReLU) + Risk Score Engine (0-100)",
            "model_family": "Multi-Layer Perceptron (MLP)",
            "total_records": len(df),
            "summary": {
                "normal": normal_cnt,
                "suspicious": suspicious_cnt,
                "attack": attack_cnt,
                "critical": critical_cnt,
                "avg_risk_score": avg_risk,
                "avg_confidence": avg_conf,
                "top_sources": top_src
            },
            "results": results
        }

    @classmethod
    def evaluate_dataframe(cls, df: pd.DataFrame, source: str = "NETWORK") -> Dict[str, Any]:
        """Evaluates a raw pandas DataFrame directly through Spark feature extraction -> MLP -> Risk -> TI."""
        _, feat_matrix, feat_names = spark_processor.process_network_dataframe(df)
        preds = mlp_pipeline.predict_batch(feat_matrix)
        results = []
        normal_cnt = suspicious_cnt = attack_cnt = critical_cnt = 0
        total_risk = total_conf = 0.0

        for i, row in df.iterrows():
            pred = preds[i] if i < len(preds) else mlp_pipeline.predict(feat_matrix[i])
            label = pred["attack_type"]
            conf = pred["confidence"]
            is_att = pred["is_attack"]
            src_ip = str(row.get("src_ip") or row.get("source_ip") or "192.168.56.104")
            dst_ip = str(row.get("dst_ip") or row.get("destination_ip") or "192.168.56.107")

            ti = threat_intel_service.lookup_ip(src_ip)
            risk = risk_engine.calculate_risk(label, conf, is_att, float(ti.get("threat_score", 0)), destination_ip=dst_ip)
            r_val = risk["risk_score"]
            r_stat = risk["risk_status"]

            if not is_att:
                normal_cnt += 1
            elif r_val >= 75:
                critical_cnt += 1
                attack_cnt += 1
            else:
                attack_cnt += 1

            total_risk += r_val
            total_conf += conf

            results.append({
                "attack_type": label,
                "confidence": conf,
                "risk_score": r_val,
                "risk_status": r_stat,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "threat_intel": ti,
                "is_attack": is_att
            })

        return {
            "total_records": len(df),
            "summary": {
                "normal": normal_cnt,
                "attack": attack_cnt,
                "critical": critical_cnt,
                "avg_risk_score": round(total_risk / max(1, len(df)), 1),
                "avg_confidence": round(total_conf / max(1, len(df)), 1)
            },
            "results": results
        }


model_router = ModelRouter()
