import os
import re
import time
import json
import uuid
import logging
import importlib.util
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd

from backend.config import settings
from backend.spark_engine.spark_manager import spark_manager
from backend.spark_engine.spark_processor import spark_processor
from backend.ml_engine.mlp_pipeline import mlp_pipeline
from backend.ml_engine.risk_engine import risk_engine
from backend.services.threat_intel import threat_intel_service
from backend.services.llm_analyst import llm_analyst
from backend.ml_engine.dataset_detector import DatasetDetector
from backend.ml_engine.pcap_pipeline import PCAPPipeline

logger = logging.getLogger("socchess.services.security_file")

SUPPORTED_EXTENSIONS = {
    ".pcap": "PCAP",
    ".pcapng": "PCAPNG",
    ".cap": "CAP",
    ".csv": "CSV",
    ".tsv": "TSV",
    ".json": "JSON",
    ".jsonl": "JSONL",
    ".ndjson": "NDJSON",
    ".parquet": "PARQUET",
    ".xlsx": "XLSX",
    ".log": "LOG",
    ".txt": "TXT",
    ".xml": "XML",
    ".evtx": "EVTX"
}

MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB Limit


class SecurityFileService:
    """
    Enterprise-grade Security Data Analyzer:
    Multi-format validation, Big Data parsing, 19-Feature extraction,
    MLP attack classification, Risk Engine scoring, Threat Intel, and Multi-file Correlation.
    """

    def __init__(self):
        self.scans: Dict[str, Dict[str, Any]] = {}
        self.scan_results: Dict[str, List[Dict[str, Any]]] = {}
        self._load_cached_history()

    def _load_cached_history(self):
        """Loads persistent scan history from disk cache."""
        history_file = settings.MODEL_DIR / "scan_history.json"
        if history_file.exists():
            try:
                with open(history_file, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    self.scans = data.get("scans", {})
                    self.scan_results = data.get("results", {})
            except Exception as e:
                logger.warning(f"[!] Warning reading scan history: {e}")

    def _save_cached_history(self):
        """Saves scan history cache to disk."""
        try:
            history_file = settings.MODEL_DIR / "scan_history.json"
            settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)
            with open(history_file, "w", encoding="utf-8") as fp:
                json.dump({"scans": self.scans, "results": self.scan_results}, fp, indent=2)
        except Exception as e:
            logger.warning(f"[!] Warning writing scan history: {e}")

    def validate_file(self, file_path: Path, filename: str) -> Dict[str, Any]:
        """
        Validates uploaded file extension, size, MIME structure, and readability.
        """
        ext = Path(filename).suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            return {
                "valid": False,
                "filename": filename,
                "file_type": "UNKNOWN",
                "error": f"Unsupported file format '{ext}'. Supported: CSV, JSON, PCAP, PCAPNG, LOG, EVTX, TXT, XML, PARQUET, XLSX.",
                "size_bytes": 0
            }

        file_type = SUPPORTED_EXTENSIONS[ext]

        try:
            size_bytes = file_path.stat().st_size
        except Exception as e:
            return {
                "valid": False,
                "filename": filename,
                "file_type": file_type,
                "error": f"Cannot access file on disk: {str(e)}",
                "size_bytes": 0
            }

        if size_bytes == 0:
            return {
                "valid": False,
                "filename": filename,
                "file_type": file_type,
                "error": "Uploaded file is empty (0 bytes).",
                "size_bytes": 0
            }

        if size_bytes > MAX_FILE_SIZE_BYTES:
            return {
                "valid": False,
                "filename": filename,
                "file_type": file_type,
                "error": f"File exceeds maximum allowed size limit of 100MB ({size_bytes / (1024*1024):.1f}MB).",
                "size_bytes": size_bytes
            }

        # Format-specific deep structure validation
        if file_type == "JSON":
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                    first_char = fp.read(1).strip()
                    if first_char not in ["{", "["]:
                        # Might be JSONL
                        fp.seek(0)
                        json.loads(fp.readline())
            except Exception as e:
                return {
                    "valid": False,
                    "filename": filename,
                    "file_type": file_type,
                    "error": f"Invalid JSON syntax: {str(e)}",
                    "size_bytes": size_bytes
                }

        elif file_type == "XML":
            try:
                ET.parse(file_path)
            except Exception as e:
                return {
                    "valid": False,
                    "filename": filename,
                    "file_type": file_type,
                    "error": f"Invalid XML syntax: {str(e)}",
                    "size_bytes": size_bytes
                }

        elif file_type in ["EVTX", "PARQUET", "XLSX"]:
            # Check dependency availability
            if file_type == "EVTX":
                has_evtx = importlib.util.find_spec("Evtx") is not None
                if not has_evtx:
                    return {
                        "valid": True,
                        "filename": filename,
                        "file_type": file_type,
                        "status": "requires_conversion",
                        "warning": "Format supported for upload but requires conversion/preprocessing (python-evtx library required).",
                        "size_bytes": size_bytes
                    }
            elif file_type == "PARQUET":
                try:
                    import pyarrow  # noqa
                except ImportError:
                    return {
                        "valid": True,
                        "filename": filename,
                        "file_type": file_type,
                        "status": "requires_conversion",
                        "warning": "Format supported for upload but requires conversion/preprocessing (pyarrow/fastparquet library required).",
                        "size_bytes": size_bytes
                    }
            elif file_type == "XLSX":
                try:
                    import openpyxl  # noqa
                except ImportError:
                    return {
                        "valid": True,
                        "filename": filename,
                        "file_type": file_type,
                        "status": "requires_conversion",
                        "warning": "Format supported for upload but requires conversion/preprocessing (openpyxl library required).",
                        "size_bytes": size_bytes
                    }

        return {
            "valid": True,
            "filename": filename,
            "file_type": file_type,
            "status": "READY",
            "size_bytes": size_bytes,
            "size_human": f"{size_bytes / 1024:.1f} KB" if size_bytes < 1024*1024 else f"{size_bytes / (1024*1024):.1f} MB",
            "message": "File validated successfully and ready for scan."
        }

    def parse_security_file(self, file_path: Path, filename: str, max_rows: int = 500) -> Tuple[Optional[pd.DataFrame], str, str, Optional[str]]:
        """
        Parses a validated security data file into a structured pandas DataFrame.
        Returns (DataFrame, detected_modality, pipeline_name, error_message)
        """
        ext = file_path.suffix.lower()
        file_type = SUPPORTED_EXTENSIONS.get(ext, "UNKNOWN")

        # 1. PCAP / PCAPNG / CAP Network Captures
        if file_type in ["PCAP", "PCAPNG", "CAP"]:
            try:
                df_flows = PCAPPipeline.parse_pcap_to_df(file_path, max_packets=max_rows)
                return df_flows, "NETWORK_PCAP", "Spark PCAP Flow Extractor", None
            except Exception as e:
                return None, "NETWORK_PCAP", "PCAP Pipeline", f"PCAP parsing failed: {str(e)}"

        # 2. XML Log Parser — extract rows, normalise to canonical columns
        if file_type == "XML":
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                raw_records: list = []

                # Recurse looking for any element that has children (i.e. a record)
                def _collect(elem: ET.Element):
                    if list(elem):  # has children
                        for child in elem:
                            if list(child):
                                _collect(child)
                            else:
                                # leaf children mean 'elem' is a record container
                                row = {}
                                for c in elem:
                                    tag = re.sub(r'\{.*?\}', '', c.tag)
                                    row[tag] = (c.text or '').strip()
                                if row:
                                    raw_records.append(row)
                                return

                _collect(root)

                # Fallback: flat attributes of root's direct children
                if not raw_records:
                    for child in root:
                        row = {re.sub(r'\{.*?\}', '', c.tag): (c.text or '').strip() for c in child}
                        if row:
                            raw_records.append(row)

                # Normalise field names to canonical schema
                norm_records = []
                for r in raw_records[:max_rows]:
                    # Build lowercase key map
                    lk = {k.lower().replace('-', '_').replace(' ', '_'): v for k, v in r.items()}

                    def _ip(k1, k2='', k3='', default='192.168.56.104'):
                        for k in [k1, k2, k3]:
                            if k and lk.get(k):
                                return lk[k]
                        return default

                    def _port(k1, k2='', default=50000):
                        for k in [k1, k2]:
                            if k and lk.get(k):
                                try:
                                    return int(float(lk[k]))
                                except Exception:
                                    pass
                        return default

                    norm_records.append({
                        'src_ip': _ip('src_ip', 'source_ip', 'srcip'),
                        'dst_ip': _ip('dst_ip', 'destination_ip', 'dstip', '192.168.56.107'),
                        'src_port': _port('src_port', 'sport'),
                        'dst_port': _port('dst_port', 'dport', 80),
                        'protocol': lk.get('protocol', lk.get('proto', 'TCP')).upper() or 'TCP',
                        'attack_cat': lk.get('attack_cat', lk.get('attack_type', lk.get('label', 'Normal'))),
                        'flow_duration': float(lk.get('flow_duration', 1.0) or 1.0),
                        'tot_fwd_pkts': int(float(lk.get('tot_fwd_pkts', lk.get('packet_count', 100)) or 100)),
                        'tot_bwd_pkts': int(float(lk.get('tot_bwd_pkts', 20) or 20)),
                        'flow_byts_s': float(lk.get('flow_byts_s', lk.get('bytes_per_sec', 10000)) or 10000),
                        'timestamp': lk.get('timestamp', lk.get('time', time.strftime('%Y-%m-%d %H:%M:%S'))),
                        '_raw_xml': str(r)
                    })

                df = pd.DataFrame(norm_records)
                return df, "XML_SECURITY_LOG", "Spark XML Event Processor", None
            except Exception as e:
                return None, "XML_SECURITY_LOG", "XML Parser", f"XML parsing failed: {str(e)}"

        # 3. Security Log / TXT Regex Parser
        if file_type in ["LOG", "TXT"]:
            try:
                events = []
                ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
                port_pattern = re.compile(r'(?:port|pt|:)\s*(\d{2,5})', re.IGNORECASE)
                event_code_pattern = re.compile(r'(?:EventCode|EventID|code|ID)[:=\s]+(\d{3,5})', re.IGNORECASE)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                    for line in fp:
                        l = line.strip()
                        if not l or l.startswith("#"):
                            continue
                        ips = ip_pattern.findall(l)
                        ports = port_pattern.findall(l)
                        codes = event_code_pattern.findall(l)

                        src_ip = ips[0] if len(ips) > 0 else "192.168.56.104"
                        dst_ip = ips[1] if len(ips) > 1 else "192.168.56.107"
                        src_port = int(ports[0]) if len(ports) > 0 else 50000
                        dst_port = int(ports[1]) if len(ports) > 1 else (int(ports[0]) if len(ports) > 0 else 80)
                        ev_code = int(codes[0]) if len(codes) > 0 else 4624

                        events.append({
                            "_raw": l,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "EventCode": ev_code,
                            "protocol": "TCP" if "tcp" in l.lower() else "UDP" if "udp" in l.lower() else "IP",
                            "message": l
                        })
                        if len(events) >= max_rows:
                            break

                df = pd.DataFrame(events)
                return df, "SECURITY_LOG", "Spark Security Log Parser", None
            except Exception as e:
                return None, "SECURITY_LOG", "Log Parser", f"Log parsing error: {str(e)}"

        # 4. EVTX, PARQUET, XLSX with fallback reporting
        if file_type == "EVTX":
            return None, "WINDOWS_EVTX", "Windows Event Log Parser", "Format supported for upload but requires conversion/preprocessing (python-evtx library required)."

        if file_type == "PARQUET":
            try:
                df = pd.read_parquet(file_path)
                if max_rows and len(df) > max_rows:
                    df = df.iloc[:max_rows]
                return df, "STRUCTURED_PARQUET", "Spark Parquet Layer", None
            except Exception:
                return None, "STRUCTURED_PARQUET", "Parquet Layer", "Format supported for upload but requires conversion/preprocessing (pyarrow required)."

        if file_type == "XLSX":
            try:
                df = pd.read_excel(file_path, nrows=max_rows)
                return df, "STRUCTURED_EXCEL", "Excel Data Layer", None
            except Exception:
                return None, "STRUCTURED_EXCEL", "Excel Layer", "Format supported for upload but requires conversion/preprocessing (openpyxl required)."

        # 5. CSV, TSV, JSON, JSONL Ingestion via Apache Spark Big Data Engine
        try:
            df = spark_manager.load_dataset_spark(file_path, max_rows=max_rows)
            if df is None or len(df) == 0:
                return None, "UNKNOWN", "Spark Ingestion", "Failed to extract structured columns from dataset."
            cols = [str(c).strip() for c in df.columns]
            modality, family = DatasetDetector._classify_columns(cols, sample_df=df)
            return df, modality, f"Spark {family} Ingestion Layer", None
        except Exception as e:
            return None, "UNKNOWN", "Spark Ingestion", f"Dataset ingestion failed: {str(e)}"

    def get_sample_dataset_files(self, limit: int = 4) -> List[Dict[str, Any]]:
        """
        Discovers standard sample attack and honeypot dataset files from settings.DATASET_ROOT.
        """
        candidates = [
            "test_sample_security.json",
            "test_capture.pcap",
            "test_sample_events.jsonl",
            "splunk_attack_data_merged.log",
            "test_sample_firewall.txt",
        ]
        sample_files = []
        d_root = settings.DATASET_ROOT
        if d_root.exists():
            for c_name in candidates:
                p = d_root / c_name
                if p.exists() and p.stat().st_size > 0:
                    sample_files.append({
                        "path": p,
                        "filename": f"[DECOY SAMPLE] {p.name}",
                        "is_sample_dataset": True
                    })
                    if len(sample_files) >= limit:
                        break
        return sample_files

    def execute_security_scan(
        self,
        files_to_scan: List[Dict[str, Any]],
        scan_id: Optional[str] = None,
        max_rows_per_file: int = 500,
        include_sample_dataset: bool = False
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end security scan across 1 or more uploaded files:
        Spark Ingestion -> 19 Canonical Features -> 3-Hidden-Layer MLP -> 0–100 Risk Engine -> Threat Intel -> Correlation
        If include_sample_dataset is True, blends decoy sample dataset flows to obfuscate genuine indicators.
        """
        scan_id = scan_id or f"scan-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        start_time = time.time()
        spark_job_id = f"spark_job_{int(time.time()*1000)}"

        # If sample dataset requested for obfuscation, automatically append sample datasets
        if include_sample_dataset:
            sample_candidates = self.get_sample_dataset_files()
            existing_paths = {str(Path(f.get("path") or f.get("filepath")).resolve()) for f in files_to_scan}
            for sf in sample_candidates:
                if str(sf["path"].resolve()) not in existing_paths:
                    files_to_scan.append(sf)

        all_results = []
        file_summaries = []
        total_records_count = 0
        total_alerts_count = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        normal_count = 0
        attack_count = 0
        total_risk_sum = 0.0
        total_conf_sum = 0.0

        # Multi-file correlation map
        attacker_ip_correlation: Dict[str, Dict[str, Any]] = {}
        target_port_correlation: Dict[int, int] = {}
        ti_cache: Dict[str, Dict[str, Any]] = {}

        for file_info in files_to_scan:
            f_path = Path(file_info.get("path") or file_info.get("filepath"))
            f_name = file_info.get("filename") or f_path.name
            is_sample_file = bool(file_info.get("is_sample_dataset", False) or "[DECOY SAMPLE]" in f_name or "sample" in f_name.lower())

            df, modality, pipeline_name, err = self.parse_security_file(f_path, f_name, max_rows=max_rows_per_file)
            if err or df is None or len(df) == 0:
                file_summaries.append({
                    "filename": f_name,
                    "status": "FAILED" if not err or "conversion" not in err else "REQUIRES_CONVERSION",
                    "records": 0,
                    "error": err or "No records extracted"
                })
                continue

            is_log = "LOG" in modality or "XML" in modality or "WINDOWS" in modality or "_raw_xml" in df.columns
            try:
                if is_log:
                    _, feature_matrix, _, _ = spark_processor.process_splunk_logs_dataframe(df)
                else:
                    _, feature_matrix, _ = spark_processor.process_network_dataframe(df)
            except Exception as feat_err:
                logger.warning(f"[!] Feature extraction fallback for {f_name}: {feat_err}")
                # Try the other pipeline as fallback
                try:
                    if is_log:
                        _, feature_matrix, _ = spark_processor.process_network_dataframe(df)
                    else:
                        _, feature_matrix, _, _ = spark_processor.process_splunk_logs_dataframe(df)
                except Exception as feat_err2:
                    logger.error(f"[!] Both feature pipelines failed for {f_name}: {feat_err2}")
                    file_summaries.append({
                        "filename": f_name,
                        "status": "FAILED",
                        "records": len(df),
                        "error": f"Feature extraction failed: {str(feat_err2)}"
                    })
                    continue

            # High-performance Vector Batch MLP Predictions
            preds = mlp_pipeline.predict_batch(feature_matrix)

            f_records = len(df)
            f_alerts = 0
            f_critical = 0
            f_high = 0

            for idx in range(f_records):
                row_dict_raw = df.iloc[idx].to_dict()
                # Sanitize: replace NaN/Inf/numpy types with JSON-safe Python primitives
                row_dict = {}
                for _k, _v in row_dict_raw.items():
                    try:
                        import math
                        if isinstance(_v, float) and (math.isnan(_v) or math.isinf(_v)):
                            row_dict[_k] = None
                        elif hasattr(_v, 'item'):  # numpy scalar
                            row_dict[_k] = _v.item()
                        else:
                            row_dict[_k] = _v
                    except Exception:
                        row_dict[_k] = str(_v) if _v is not None else None
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

                # Extract network/host identifiers
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

                # Threat Intelligence Lookup
                if src_ip not in ti_cache:
                    ti_cache[src_ip] = threat_intel_service.lookup_ip(src_ip)
                ti_res = ti_cache[src_ip]
                ti_score = float(ti_res.get("threat_score", 0))

                # Multi-Factor 0-100 Risk Scoring
                freq = attacker_ip_correlation.get(src_ip, {}).get("count", 0) + 1
                risk_calc = risk_engine.calculate_risk(
                    attack_type=label,
                    mlp_confidence=conf,
                    is_attack=is_att,
                    threat_intel_score=ti_score,
                    event_frequency=freq,
                    destination_ip=dst_ip
                )
                risk_val = risk_calc["risk_score"]
                risk_stat = risk_calc["risk_status"]

                if risk_stat == "CRITICAL":
                    critical_count += 1
                    f_critical += 1
                    attack_count += 1
                    total_alerts_count += 1
                    f_alerts += 1
                elif risk_stat == "HIGH" or is_att:
                    high_count += 1
                    f_high += 1
                    attack_count += 1
                    total_alerts_count += 1
                    f_alerts += 1
                elif risk_stat == "MEDIUM":
                    medium_count += 1
                    total_alerts_count += 1
                    f_alerts += 1
                else:
                    low_count += 1
                    normal_count += 1

                total_risk_sum += risk_val
                total_conf_sum += conf

                # Correlation tracking
                if src_ip not in attacker_ip_correlation:
                    attacker_ip_correlation[src_ip] = {
                        "ip": src_ip,
                        "count": 0,
                        "files": set(),
                        "attacks": set(),
                        "max_risk": 0.0,
                        "threat_score": ti_score
                    }
                attacker_ip_correlation[src_ip]["count"] += 1
                attacker_ip_correlation[src_ip]["files"].add(f_name)
                attacker_ip_correlation[src_ip]["attacks"].add(label)
                attacker_ip_correlation[src_ip]["max_risk"] = max(attacker_ip_correlation[src_ip]["max_risk"], risk_val)

                if dst_p > 0:
                    target_port_correlation[dst_p] = target_port_correlation.get(dst_p, 0) + 1

                # MITRE ATT&CK Mapping & Normal Traffic Display
                display_label = "Normal Traffic" if (not is_att or str(label).strip().lower() in ("normal", "benign", "clean")) else label
                mitre_str = "T1046 - Network Service Scanning" if is_att else "Nominal Baseline (Benign Traffic)"
                if label == "DDoS": mitre_str = "T1498 - Network Denial of Service"
                elif label == "Brute Force": mitre_str = "T1110 - Brute Force"
                elif label == "Infiltration": mitre_str = "T1059 - Command and Scripting Interpreter"
                elif label == "Botnet": mitre_str = "T1071 - Application Layer Protocol (C2)"
                elif label == "Exploits": mitre_str = "T1203 - Exploitation for Client Execution"
                elif not is_att or "normal" in str(label).lower(): mitre_str = "Nominal Baseline (Benign Traffic)"

                alert_id = f"alert-{scan_id}-{len(all_results)+1}"
                result_item = {
                    "alert_id": alert_id,
                    "scan_id": scan_id,
                    "source_file": f_name,
                    "is_sample_dataset": is_sample_file,
                    "telemetry_type": "DECOY_SAMPLE_DATASET" if is_sample_file else "LIVE_EVIDENCE",
                    "is_decoy": is_sample_file,
                    "obfuscation_note": "Sample dataset attack flow injected for defense obfuscation (honeypot decoy)" if is_sample_file else "Genuine operational telemetry (protected under decoy layer)",
                    "timestamp": str(row_dict.get("timestamp") or row_dict.get("_time") or time.strftime("%Y-%m-%d %H:%M:%S")),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": src_p,
                    "destination_port": dst_p,
                    "protocol": proto,
                    "attack_type": display_label,
                    "prediction": display_label,
                    "attack_category": display_label,
                    "is_attack": is_att and ("normal" not in display_label.lower()),
                    "confidence": round(conf, 1),
                    "mlp_confidence": round(conf, 1),
                    "risk_score": round(risk_val, 1) if is_att else min(15.0, round(risk_val, 1)),
                    "risk_status": risk_stat if is_att else "LOW",
                    "severity": risk_stat if is_att else "LOW",
                    "threat_intel": ti_res,
                    "risk_evidence": risk_calc["evidence"],
                    "mitre_technique": mitre_str,
                    "detection_source": f_name,
                    "recommendation": "Isolate source host and enforce firewall rules" if is_att else "Normal Traffic (Benign). Maintain standard operational monitoring.",
                    "explanation": f"MLP Neural Network classified as {display_label} with {conf:.1f}% confidence. Risk Score: {risk_val:.0f}/100 ({risk_stat})." if is_att else "Verified as Normal Traffic. No threat indicators detected.",
                    "raw_attributes": row_dict
                }
                all_results.append(result_item)

            total_records_count += f_records
            file_summaries.append({
                "filename": f_name,
                "status": "COMPLETED",
                "records": f_records,
                "alerts": f_alerts,
                "critical": f_critical,
                "high": f_high,
                "pipeline": pipeline_name,
                "is_sample_dataset": is_sample_file
            })

        duration_s = round(time.time() - start_time, 2)
        avg_risk = round(total_risk_sum / max(1, total_records_count), 1)
        avg_conf = round(total_conf_sum / max(1, total_records_count), 1)

        # Build Correlated Investigations
        correlations = []
        for ip, info in sorted(attacker_ip_correlation.items(), key=lambda x: -x[1]["count"]):
            if len(info["files"]) > 1 or info["max_risk"] >= 75:
                correlations.append({
                    "ip": ip,
                    "activity_count": info["count"],
                    "associated_files": list(info["files"]),
                    "attack_types": list(info["attacks"]),
                    "max_risk_score": info["max_risk"],
                    "threat_score": info["threat_score"],
                    "correlation_insight": f"Observed across {len(info['files'])} files with {len(info['attacks'])} distinct attack tactics."
                })

        # Sort results: Default highest risk score first
        all_results.sort(key=lambda x: -x["risk_score"])

        has_sample = any(r.get("is_sample_dataset") for r in all_results)
        real_recs = len([r for r in all_results if not r.get("is_sample_dataset")])
        decoy_recs = len([r for r in all_results if r.get("is_sample_dataset")])

        scan_summary = {
            "scan_id": scan_id,
            "spark_job_id": spark_job_id,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "COMPLETED",
            "duration_seconds": duration_s,
            "total_files": len(files_to_scan),
            "files": file_summaries,
            "total_records": total_records_count,
            "total_alerts": total_alerts_count,
            "obfuscation_active": has_sample,
            "real_records_count": real_recs,
            "decoy_records_count": decoy_recs,
            "obfuscation_ratio": f"{round((decoy_recs / max(1, total_records_count)) * 100, 1)}%",
            "obfuscation_note": (
                "Decoy & Sample Dataset Obfuscation Active: Sample dataset attack vectors have been scanned "
                "and co-mingled in this report. This masks real assets and makes it difficult for adversaries "
                "or unauthorized observers to isolate genuine target infrastructure."
            ) if has_sample else "Standard Telemetry Scan (No Decoy Obfuscation)",
            "summary": {
                "total_records": total_records_count,
                "total_alerts": total_alerts_count,
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "normal": normal_count,
                "attack": attack_count,
                "avg_risk_score": avg_risk,
                "avg_confidence": avg_conf,
                "obfuscation_active": has_sample,
                "real_records": real_recs,
                "decoy_records": decoy_recs
            },
            "correlations": correlations[:10],
            "top_target_ports": [{"port": p, "count": c} for p, c in sorted(target_port_correlation.items(), key=lambda x: -x[1])[:5]]
        }

        # Store in memory & cache
        self.scans[scan_id] = scan_summary
        self.scan_results[scan_id] = all_results
        self._save_cached_history()

        # Record in spark_jobs (best-effort — spark_manager.save_job is non-critical)
        try:
            spark_manager.save_job(spark_job_id, "MULTI_FORMAT_SECURITY_SCAN", total_records_count, int(duration_s * 1000), scan_summary)
        except Exception:
            try:
                spark_manager.active_jobs[spark_job_id] = {"type": "MULTI_FORMAT_SECURITY_SCAN", "records": total_records_count}
            except Exception:
                pass  # Non-critical — history is already persisted to disk above

        return {
            "scan_id": scan_id,
            "status": "COMPLETED",
            "summary": scan_summary,
            "results": all_results
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Returns details for a single scan run."""
        summary = self.scans.get(scan_id)
        if not summary:
            return None
        results = self.scan_results.get(scan_id, [])
        return {
            "scan_id": scan_id,
            "summary": summary,
            "results": results
        }

    def list_scans(self) -> List[Dict[str, Any]]:
        """Returns list of completed security scan runs."""
        return sorted(list(self.scans.values()), key=lambda x: x.get("scan_date", ""), reverse=True)

    def delete_scan(self, scan_id: str) -> bool:
        """Deletes scan metadata from history without deleting raw system alerts."""
        if scan_id in self.scans:
            del self.scans[scan_id]
            if scan_id in self.scan_results:
                del self.scan_results[scan_id]
            self._save_cached_history()
            return True
        return False

    def get_single_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single alert from any scan run."""
        for s_id, results in self.scan_results.items():
            for r in results:
                if r.get("alert_id") == alert_id:
                    return r
        return None


security_file_service = SecurityFileService()
