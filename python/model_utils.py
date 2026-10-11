#!/usr/bin/env python3
"""
================================================================================
SOC CHESS -- Shared ML Pipeline Utilities
================================================================================
Shared utility functions used across:
  - dataset_processor.py
  - prepare_ml_data.py
  - train_network_models.py
  - train_splunk_models.py
  - predict_network.py
  - predict_splunk.py
================================================================================
"""

import os
import re
import sys
import json
import logging
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# PROJECT PATHS
# ---------------------------------------------------------------------------
BASE_DIR      = Path(__file__).resolve().parent.parent   # soc-chess root
PYTHON_DIR    = BASE_DIR / "python"
DATASETS_DIR  = BASE_DIR / "datasets"
PROCESSED_DIR = DATASETS_DIR / "processed"
MODELS_DIR         = BASE_DIR / "models"
MODELS_NETWORK_DIR = MODELS_DIR / "network"
MODELS_SPLUNK_DIR  = MODELS_DIR / "splunk"
NETWORK_DIR        = DATASETS_DIR / "network"
SPLUNK_DIR         = DATASETS_DIR / "Splunk-Attack-Data" / "datasets"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_NETWORK_DIR.mkdir(parents=True, exist_ok=True)
MODELS_SPLUNK_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
LOG_FORMAT  = "%(asctime)s [%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

def setup_logger(name: str, log_file: Path, level=logging.INFO) -> logging.Logger:
    """Set up a logger writing to both file and console."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(fh)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(ch)
    return logger

PROCESSING_LOG = PYTHON_DIR / "dataset_processing.log"
TRAINING_LOG   = PYTHON_DIR / "ml_training.log"

# ---------------------------------------------------------------------------
# GIT LFS DETECTION
# ---------------------------------------------------------------------------
GIT_LFS_MAX_SIZE = 600

def is_git_lfs_pointer(file_path: Path) -> bool:
    """Return True if the file is a Git LFS pointer (not the real object)."""
    try:
        if file_path.stat().st_size > GIT_LFS_MAX_SIZE:
            return False
        with open(file_path, "rb") as f:
            header = f.read(50)
        return header.startswith(b"version https://git-lfs.github.com")
    except Exception:
        return False

# ---------------------------------------------------------------------------
# SUPPORTED EXTENSIONS
# ---------------------------------------------------------------------------
NETWORK_EXTENSIONS  = {".csv", ".log", ".json", ".jsonl", ".ndjson", ".xml", ".txt"}
SPLUNK_EXTENSIONS   = {".log", ".csv", ".json", ".jsonl", ".ndjson", ".xml", ".txt"}
METADATA_EXTENSIONS = {".yml", ".yaml"}

SPLUNK_SKIP_NAMES = {
    ".github", "bin", "environments", "total_replay",
    "README.md", "LICENSE", ".gitignore", ".gitattributes",
    ".git", ".gitkeep"
}

# ---------------------------------------------------------------------------
# NETWORK COLUMN SYNONYM MAP
# canonical_name -> [known aliases (lowercase)]
# ---------------------------------------------------------------------------
NETWORK_SYNONYM_MAP: Dict[str, List[str]] = {
    "source_ip":         ["src_ip","srcip","source ip","src ip","ip_src","ip.src"],
    "destination_ip":    ["dst_ip","dstip","destination ip","dst ip","ip_dst","ip.dst"],
    "source_port":       ["src_port","srcport","sport","source port","src port","tcp.srcport","udp.srcport"],
    "destination_port":  ["dst_port","dstport","dsport","dport","destination port","dst port","tcp.dstport","udp.dstport"],
    "protocol":          ["proto","protocol_type","ip.proto"],
    "timestamp":         ["stime","ltime","start time","time","date","ts","flow start"],
    "flow_duration":     ["duration","dur","flow duration","flow_dur"],
    "fwd_bytes":         ["totlen_fwd_pkts","sbytes","src_bytes","total length of fwd packets","fwd_pkt_length_total"],
    "bwd_bytes":         ["totlen_bwd_pkts","dbytes","dst_bytes","total length of bwd packets","bwd_pkt_length_total"],
    "fwd_packets":       ["tot_fwd_pkts","spkts","total fwd packets","fwd_packet_count"],
    "bwd_packets":       ["tot_bwd_pkts","dpkts","total backward packets","bwd_packet_count"],
    "flow_bytes_s":      ["flow bytes/s","flow_bytes/s","flow_byts_s"],
    "flow_packets_s":    ["flow packets/s","flow_packets/s","flow_pkts_s"],
    "fwd_pkt_len_mean":  ["fwd packet length mean","smeansz","smean"],
    "bwd_pkt_len_mean":  ["bwd packet length mean","dmeansz","dmean"],
    "syn_flag_cnt":      ["syn flag count","syn_flag_count"],
    "ack_flag_cnt":      ["ack flag count","ack_flag_count"],
    "psh_flag_cnt":      ["psh flag count","psh_flag_count"],
    "fin_flag_cnt":      ["fin flag count","fin_flag_count"],
    "init_fwd_win_byts": ["init_win_bytes_forward","init fwd win byts","swin"],
    "init_bwd_win_byts": ["init_win_bytes_backward","init bwd win byts","dwin"],
    "state":             ["state","tcp_state"],
    "service":           ["service","svc"],
    "attack_category":   ["attack_cat","attackcat","category"],
}

LABEL_COLUMNS = [
    "Label","label","Class","class","Attack","attack",
    "attack_cat","Attack_cat","category","Category","target","Target"
]

NORMAL_LABELS = {"benign","normal","normal.","background","0","legitimate","non-attack"}
UNKNOWN_LABEL = "UNKNOWN"

def normalize_label(raw_label: Any) -> Tuple[str, str]:
    """Normalize raw label to (label, attack_category). Never fabricates."""
    if raw_label is None or (isinstance(raw_label, float) and np.isnan(raw_label)):
        return UNKNOWN_LABEL, ""
    s = str(raw_label).strip()
    if not s or s.lower() in ("nan","none","null",""):
        return UNKNOWN_LABEL, ""
    lower = s.lower()
    if lower in NORMAL_LABELS:
        return "NORMAL", ""
    try:
        num = float(lower)
        if num == 0:
            return "NORMAL", ""
        return "ATTACK", f"numeric_{int(num)}"
    except ValueError:
        pass
    category = re.sub(r"\s+","_",s.strip()).upper()
    return "ATTACK", category

def normalize_network_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename DataFrame columns to canonical network names."""
    reverse = {}
    for canonical, aliases in NETWORK_SYNONYM_MAP.items():
        for alias in aliases:
            reverse[alias.lower().strip()] = canonical
    rename_map = {}
    for col in df.columns:
        key = col.strip().lower()
        if key in reverse and col != reverse[key]:
            canonical = reverse[key]
            if canonical not in df.columns:
                rename_map[col] = canonical
    if rename_map:
        df = df.rename(columns=rename_map)
    return df

# ---------------------------------------------------------------------------
# MITRE EXTRACTION
# ---------------------------------------------------------------------------
MITRE_RE = re.compile(r"(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)

def extract_mitre_from_path(path: Union[str, Path]) -> str:
    matches = MITRE_RE.findall(str(path).replace("\\", "/"))
    return matches[-1].upper() if matches else ""

# ---------------------------------------------------------------------------
# THREAT LEVEL
# ---------------------------------------------------------------------------
def confidence_to_threat_level(confidence: float, prediction: str) -> str:
    if prediction == "NORMAL":
        return "LOW"
    if confidence >= 0.90:
        return "CRITICAL"
    if confidence >= 0.75:
        return "HIGH"
    if confidence >= 0.50:
        return "MEDIUM"
    return "LOW"

# ---------------------------------------------------------------------------
# SAFE JSON I/O
# ---------------------------------------------------------------------------
class _NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer,)):   return int(obj)
        if isinstance(obj, (np.floating,)):  return float(obj)
        if isinstance(obj, np.ndarray):      return obj.tolist()
        if isinstance(obj, (datetime.date, datetime.datetime)): return obj.isoformat()
        return super().default(obj)

def safe_json_write(data: Any, path: Path, indent: int = 4) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, cls=_NumpyEncoder)

def safe_json_read(path: Path) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# PROGRESS HELPERS
# ---------------------------------------------------------------------------
def print_progress(current: int, total: int, label: str = "") -> None:
    width = 40
    pct   = current / total if total > 0 else 0
    filled = int(width * pct)
    bar   = "#" * filled + "-" * (width - filled)
    tag   = f" {label[:35]}" if label else ""
    print(f"\r  [{bar}] {current}/{total}{tag}", end="", flush=True)
    if current >= total:
        print()

def print_section(title: str) -> None:
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def print_subsection(title: str) -> None:
    print("\n" + "-" * 60)
    print(f"  {title}")
    print("-" * 60)

# ---------------------------------------------------------------------------
# METRICS
# ---------------------------------------------------------------------------
def compute_metrics(y_true, y_pred, label_encoder=None) -> Dict[str, Any]:
    """
    Compute real classification metrics from actual test predictions.
    All values come from y_true vs y_pred -- nothing is fabricated.
    """
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, classification_report, confusion_matrix
    )
    accuracy    = accuracy_score(y_true, y_pred)
    precision   = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    recall      = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    macro_f1    = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    labels = list(range(len(label_encoder.classes_))) if label_encoder else None
    target_names = [str(c) for c in label_encoder.classes_] if label_encoder else None
    cr = classification_report(y_true, y_pred, labels=labels, target_names=target_names, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    return {
        "accuracy":              round(float(accuracy), 6),
        "precision":             round(float(precision), 6),
        "recall":                round(float(recall), 6),
        "macro_f1":              round(float(macro_f1), 6),
        "weighted_f1":           round(float(weighted_f1), 6),
        "classification_report": cr,
        "confusion_matrix":      cm,
    }

# ---------------------------------------------------------------------------
# FILE DISCOVERY
# ---------------------------------------------------------------------------
def discover_files(root: Path, extensions: set, skip_names: set = None) -> List[Path]:
    found = []
    skip  = skip_names or set()
    for item in root.rglob("*"):
        if item.is_file():
            if any(part in skip for part in item.parts):
                continue
            if item.name in skip:
                continue
            if item.suffix.lower() in extensions:
                found.append(item)
    return sorted(found)

def discover_yaml_files(root: Path, skip_names: set = None) -> List[Path]:
    return discover_files(root, METADATA_EXTENSIONS, skip_names)

# ---------------------------------------------------------------------------
# KNOWN NETWORK SCHEMAS (headerless datasets)
# ---------------------------------------------------------------------------
UNSW_COLS_49 = [
    "srcip","sport","dstip","dsport","proto","state","dur",
    "sbytes","dbytes","sttl","dttl","sloss","dloss","service",
    "Sload","Dload","Spkts","Dpkts","swin","dwin","stcpb","dtcpb",
    "smeansz","dmeansz","trans_depth","res_bdy_len","Sjit","Djit",
    "Stime","Ltime","Sintpkt","Dintpkt","tcprtt","synack","ackdat",
    "is_sm_ips_ports","ct_state_ttl","ct_flw_http_mthd","is_ftp_login",
    "ct_ftp_cmd","ct_srv_src","ct_srv_dst","ct_dst_ltm","ct_src_ltm",
    "ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm",
    "attack_cat","Label"
]

KDD_COLS_43 = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "Label","difficulty_level"
]

KDD_COLS_42 = KDD_COLS_43[:-1]

def detect_network_schema(file_path: Path, cols_lower: set) -> str:
    name = file_path.name.upper()
    if "UNSW" in name or "NB15" in name:
        return "unsw_nb15"
    if "KDD" in name or "NSL" in name:
        return "kdd"
    if "ISCX" in name or "CIC" in name:
        return "cicids"
    if "srcip" in cols_lower or "dstip" in cols_lower:
        return "unsw_nb15"
    if "protocol_type" in cols_lower and "flag" in cols_lower:
        return "kdd"
    if "flow duration" in cols_lower or "flow_duration" in cols_lower:
        return "cicids"
    return "generic"

# ---------------------------------------------------------------------------
# SPLUNK YAML PARSER
# ---------------------------------------------------------------------------
def parse_splunk_yaml(yaml_path: Path, splunk_datasets_root: Path) -> List[Dict[str, Any]]:
    """
    Parse a Splunk Attack Data YAML and return enriched metadata records.
    These are REAL records from actual YAML files -- not fabricated event data.
    Label = ATTACK because all YAML scenarios are known attack simulations.
    """
    try:
        import yaml
    except ImportError:
        return []

    records = []
    try:
        with open(yaml_path, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
    except Exception:
        return records

    if not isinstance(data, dict):
        return records

    author      = str(data.get("author","")).strip()
    description = str(data.get("description","")).strip()
    environment = str(data.get("environment","")).strip()
    directory   = str(data.get("directory","")).strip()
    date_str    = str(data.get("date","")).strip()

    mitre_technique = extract_mitre_from_path(yaml_path)

    try:
        rel = yaml_path.relative_to(splunk_datasets_root)
        top_category = rel.parts[0] if rel.parts else ""
        sub_category = rel.parts[1] if len(rel.parts) > 1 else ""
    except Exception:
        top_category = ""
        sub_category = directory

    attack_category = sub_category or directory or top_category

    datasets_entries = data.get("datasets", [])
    if not isinstance(datasets_entries, list):
        datasets_entries = []
    if not datasets_entries:
        datasets_entries = [{}]

    for entry in datasets_entries:
        if not isinstance(entry, dict):
            continue
        log_name   = str(entry.get("name","")).strip()
        sourcetype = str(entry.get("sourcetype","")).strip()
        source     = str(entry.get("source","")).strip()

        data_type = "windows_event"
        st_lower  = sourcetype.lower()
        if "sysmon" in st_lower:
            data_type = "windows_sysmon"
        elif "security" in st_lower:
            data_type = "windows_security"
        elif "powershell" in st_lower:
            data_type = "windows_powershell"

        try:
            rel_path = str(yaml_path.relative_to(splunk_datasets_root.parent.parent)).replace("\\","/")
        except Exception:
            rel_path = yaml_path.name

        record = {
            "timestamp":       date_str or None,
            "source_ip":       None,
            "destination_ip":  None,
            "source_port":     None,
            "destination_port":None,
            "protocol":        None,
            "event_code":      None,
            "event_id":        None,
            "event_type":      log_name or None,
            "action":          None,
            "status":          None,
            "username":        None,
            "hostname":        None,
            "process_name":    None,
            "command_line":    None,
            "file_name":       None,
            "hash":            None,
            "url":             None,
            "bytes_in":        None,
            "bytes_out":       None,
            "duration":        None,
            "attack_category": attack_category,
            "attack_scenario": directory,
            "mitre_technique": mitre_technique,
            "original_label":  attack_category,
            "label":           "ATTACK",
            "source_dataset":  "Splunk-Attack-Data",
            "source_file":     yaml_path.name,
            "relative_path":   rel_path,
            "data_type":       data_type,
            "log_sourcetype":  sourcetype,
            "log_source":      source,
            "description":     description[:200] if description else None,
            "author":          author,
            "environment":     environment,
            "raw_message":     None,
        }
        records.append(record)

    return records

# ---------------------------------------------------------------------------
# MODEL METADATA
# ---------------------------------------------------------------------------
def build_model_metadata(
    model_name: str, algorithm: str, dataset: str, pipeline: str,
    metrics: Dict[str, Any], model_path: Path,
    n_train: int, n_test: int, n_features: int,
    classes: List[str], feature_names: List[str],
    preprocessing_version: str = "1.0"
) -> Dict[str, Any]:
    return {
        "model_name":           model_name,
        "algorithm":            algorithm,
        "dataset":              dataset,
        "pipeline":             pipeline,
        "training_date":        datetime.datetime.now().isoformat(),
        "training_records":     n_train,
        "testing_records":      n_test,
        "number_of_features":   n_features,
        "number_of_classes":    len(classes),
        "classes":              classes,
        "feature_names":        feature_names,
        "metrics":              metrics,
        "model_path":           str(model_path),
        "preprocessing_version":preprocessing_version,
    }
