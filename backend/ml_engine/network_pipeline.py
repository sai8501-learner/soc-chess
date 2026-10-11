import os
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

logger = logging.getLogger("socchess.ml.network_pipeline")

def get_device_label(ip: str) -> str:
    """Provides human-readable device attribution for IP addresses."""
    ip_str = str(ip).strip()
    if ip_str.endswith(".104"):
        return "Attacker Host (192.168.56.104)"
    elif ip_str.endswith(".107"):
        return "Victim Endpoint (192.168.56.107)"
    elif ip_str in ["8.8.8.8", "8.8.4.4"]:
        return "Google Public DNS"
    elif ip_str in ["1.1.1.1", "1.0.0.1"]:
        return "Cloudflare Public DNS"
    elif ip_str.startswith("192.168.") or ip_str.startswith("10.") or ip_str.startswith("172.16."):
        return f"Internal Host ({ip_str})"
    return f"External Host ({ip_str})"

def get_mitre(attack_type: str) -> Dict[str, str]:
    """Maps predicted attack category to MITRE ATT&CK technique."""
    t = str(attack_type).lower()
    if any(k in t for k in ["syn flood", "icmp flood", "dos", "ddos", "hulk", "goldeneye", "slowloris"]):
        return {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}
    elif any(k in t for k in ["port scan", "portscan", "network scan", "host discovery", "service enumeration", "probe", "scan", "recon"]):
        return {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}
    elif any(k in t for k in ["bruteforce", "brute force", "brute", "ssh", "rdp", "ftp", "web login", "patator"]):
        return {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
    elif any(k in t for k in ["arp", "spoof"]):
        return {"id": "T1557.002", "name": "Adversary-in-the-Middle: ARP Poisoning", "tactic": "Credential Access"}
    elif any(k in t for k in ["dns tunnel", "tunneling"]):
        return {"id": "T1071.004", "name": "DNS Tunneling", "tactic": "Command and Control"}
    elif any(k in t for k in ["exfiltration", "data exfil"]):
        return {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}
    elif any(k in t for k in ["bot", "c2", "infilteration", "infiltration", "backdoor"]):
        return {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}
    elif any(k in t for k in ["directory traversal", "path traversal"]):
        return {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"}
    elif any(k in t for k in ["web", "xss", "injection", "sql"]):
        return {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
    elif any(k in t for k in ["fuzz", "exploit"]):
        return {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}
    return {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}


# Canonical synonym dictionary
NETWORK_SYNONYMS: Dict[str, List[str]] = {
    "dst_port": ["destination port", "dst port", "dport", "destination_port", "dst_port", "dstport", "dsport"],
    "src_port": ["source port", "src port", "sport", "source_port", "src_port", "srcport", "srcip"],
    "protocol": ["protocol", "proto", "protocol_type"],
    "flow_duration": ["flow duration", "duration", "flow_duration", "dur"],
    "total_fwd_packets": ["total fwd packets", "tot fwd pkts", "fwd_packets", "total_fwd_pkts", "spkts", "tot fwd packets"],
    "total_bwd_packets": ["total backward packets", "tot bwd pkts", "bwd_packets", "total_bwd_pkts", "dpkts", "tot bwd packets"],
    "total_fwd_length": ["total length of fwd packets", "totlen fwd pkts", "fwd_bytes", "sbytes", "totlen fwd packets", "src_bytes"],
    "total_bwd_length": ["total length of bwd packets", "totlen bwd pkts", "bwd_bytes", "dbytes", "totlen bwd packets", "dst_bytes"],
    "fwd_packet_length_max": ["fwd packet length max", "fwd pkt len max", "fwd_pkt_len_max", "smeansz"],
    "fwd_packet_length_min": ["fwd packet length min", "fwd pkt len min", "fwd_pkt_len_min"],
    "fwd_packet_length_mean": ["fwd packet length mean", "fwd pkt len mean", "fwd_pkt_len_mean"],
    "bwd_packet_length_max": ["bwd packet length max", "bwd pkt len max", "bwd_pkt_len_max", "dmeansz"],
    "bwd_packet_length_min": ["bwd packet length min", "bwd pkt len min", "bwd_pkt_len_min"],
    "bwd_packet_length_mean": ["bwd packet length mean", "bwd pkt len mean", "bwd_pkt_len_mean"],
    "flow_bytes_per_sec": ["flow bytes/s", "flow byts/s", "flow_bytes_s", "rate", "flow_bytes_per_sec", "sload", "dload"],
    "flow_packets_per_sec": ["flow packets/s", "flow pkts/s", "flow_packets_s", "flow_packets_per_sec"],
    "flow_iat_mean": ["flow iat mean", "flow_iat_mean", "sintpkt", "dintpkt"],
    "flow_iat_std": ["flow iat std", "flow_iat_std"],
    "fwd_iat_total": ["fwd iat total", "fwd iat tot", "fwd_iat_total", "sinjit", "sjit"],
    "bwd_iat_total": ["bwd iat total", "bwd iat tot", "bwd_iat_total", "dinjit", "djit"],
    "fwd_packets_per_sec": ["fwd packets/s", "fwd pkts/s", "fwd_packets_per_sec"],
    "bwd_packets_per_sec": ["bwd packets/s", "bwd pkts/s", "bwd_packets_per_sec"],
    "packet_length_min": ["min packet length", "pkt len min", "packet_length_min"],
    "packet_length_max": ["max packet length", "pkt len max", "packet_length_max"],
    "packet_length_mean": ["packet length mean", "pkt len mean", "packet_length_mean", "packet_len", "packet_length"],
    "packet_length_std": ["packet length std", "pkt len std", "packet_length_std"],
    "fin_flag_count": ["fin flag count", "fin flag cnt", "fin_flag_count"],
    "syn_flag_count": ["syn flag count", "syn flag cnt", "syn_flag_count", "syn_count", "synack"],
    "rst_flag_count": ["rst flag count", "rst flag cnt", "rst_flag_count"],
    "psh_flag_count": ["psh flag count", "psh flag cnt", "psh_flag_count"],
    "ack_flag_count": ["ack flag count", "ack flag cnt", "ack_flag_count", "ackdat"],
    "urg_flag_count": ["urg flag count", "urg flag cnt", "urg_flag_count"],
    "avg_packet_size": ["average packet size", "pkt size avg", "avg_packet_size"],
    "init_fwd_win_bytes": ["init_win_bytes_forward", "init fwd win byts", "init_fwd_win_bytes", "swin"],
    "init_bwd_win_bytes": ["init_win_bytes_backward", "init bwd win byts", "init_bwd_win_bytes", "dwin"]
}

NETWORK_IDENTIFIERS = {
    "id", "flow id", "flow_id", "source ip", "src ip", "src_ip", "source_ip", "srcip",
    "destination ip", "dst ip", "dst_ip", "destination_ip", "dstip", "timestamp",
    "time", "date", "simillarhttp", "unnamed: 0", "unnamed: 0.1", "row_id",
    "sttl", "dttl", "sloss", "dloss", "ct_state_ttl", "ct_srv_src", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login",
    "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
    "stime", "ltime", "start time", "last time", "guid", "hash", "session_id", "url"
}


class NetworkMLPipeline:
    """
    Dedicated ML Pipeline for Network Flow datasets (CICIDS, UNSW-NB15, KDD, PCAP/TShark flows).
    Guarantees strict memory safety, non-explosive feature scaling, and high-precision threat classification.
    """

    @staticmethod
    def canonicalize_column(col: str) -> str:
        clean = str(col).strip().lower().replace("_", " ").replace("-", " ")
        for canonical, synonyms in NETWORK_SYNONYMS.items():
            for syn in synonyms:
                if clean == syn.lower() or clean.replace(" ", "") == syn.lower().replace(" ", ""):
                    return canonical
        return col.strip()

    @staticmethod
    def normalize_network_label(val: Any) -> str:
        if val is None or pd.isna(val):
            return "Normal"
        s = str(val).strip()
        s_low = s.lower()
        if s_low in ["benign", "normal", "0", "0.0", "clean", "normal traffic", "normal."]:
            return "Normal"
        if s_low in ["1", "1.0", "attack"]:
            return "Attack"
        if "slowhttptest" in s_low: return "DoS-SlowHTTPTest"
        if "goldeneye" in s_low: return "DoS-GoldenEye"
        if "hulk" in s_low: return "DoS-Hulk"
        if "slowloris" in s_low: return "DoS-Slowloris"
        if "ftp" in s_low and "brute" in s_low: return "FTP-BruteForce"
        if "ssh" in s_low and "brute" in s_low: return "SSH-BruteForce"
        if "web" in s_low and "brute" in s_low: return "Web-BruteForce"
        if "loic-http" in s_low: return "DDoS-LOIC-HTTP"
        if "loic-udp" in s_low: return "DDoS-LOIC-UDP"
        if "hoic" in s_low: return "DDoS-HOIC"
        if "portscan" in s_low or "port scan" in s_low or "ipsweep" in s_low: return "PortScan"
        if "ddos" in s_low: return "DDoS"
        if "dos" in s_low or "neptune" in s_low or "smurf" in s_low or "back" in s_low: return "DoS"
        if "bot" in s_low: return "Botnet"
        if "infilteration" in s_low or "infiltration" in s_low: return "Infiltration"
        if "sql" in s_low: return "SQLInjection"
        if "xss" in s_low: return "XSS"
        if "backdoor" in s_low: return "Backdoor"
        if "reconnaissance" in s_low or "satan" in s_low or "nmap" in s_low: return "Reconnaissance"
        if "exploits" in s_low or "warezclient" in s_low or "guess_passwd" in s_low: return "Exploits"
        if "generic" in s_low: return "Generic"
        if "fuzzers" in s_low: return "Fuzzers"
        if "analysis" in s_low: return "Analysis"
        if "worms" in s_low: return "Worms"
        if "shellcode" in s_low or "buffer_overflow" in s_low: return "Shellcode"
        return s

    @classmethod
    def train_network_model(
        cls,
        labeled_dfs: List[Tuple[pd.DataFrame, str]],
        model_dir: Path,
        version: str = "NET-RF-001",
        n_estimators: int = 150,
        classification_mode: str = "multiclass"
    ) -> Dict[str, Any]:
        """
        Trains Supervised Random Forest for all compatible network flow datasets.
        """
        model_dir.mkdir(parents=True, exist_ok=True)
        version_dir = model_dir / version
        version_dir.mkdir(parents=True, exist_ok=True)

        processed_dfs = []
        for df, target_col in labeled_dfs:
            if target_col not in df.columns:
                continue

            clean_df = df.copy()
            clean_df.columns = [str(c).strip() for c in clean_df.columns]

            # Canonicalize column names
            rename_map = {c: cls.canonicalize_column(c) for c in clean_df.columns if c != target_col}
            clean_df.rename(columns=rename_map, inplace=True)
            clean_df = clean_df.loc[:, ~clean_df.columns.duplicated()].copy()

            # Target processing
            if classification_mode == "binary":
                y_s = clean_df[target_col].apply(lambda v: "Normal" if cls.normalize_network_label(v).lower() == "normal" else "Attack")
            else:
                y_s = clean_df[target_col].apply(cls.normalize_network_label)

            clean_df["target_normalized"] = y_s
            clean_df.drop(columns=[target_col], inplace=True)

            # Drop identifiers
            drop_cols = [c for c in clean_df.columns if c.lower() in NETWORK_IDENTIFIERS or "unnamed" in c.lower()]
            clean_df.drop(columns=drop_cols, inplace=True, errors="ignore")
            clean_df = clean_df.loc[:, ~clean_df.columns.duplicated()].copy()
            clean_df.reset_index(drop=True, inplace=True)

            processed_dfs.append(clean_df)

        if not processed_dfs:
            raise ValueError("No valid Network datasets available for training.")

        combined_df = pd.concat(processed_dfs, axis=0, ignore_index=True)
        combined_df.replace(["Infinity", "infinity", "inf", "-inf", np.inf, -np.inf], np.nan, inplace=True)

        y_raw = combined_df["target_normalized"].astype(str)
        X_raw = combined_df.drop(columns=["target_normalized"])

        # Feature processing & high-cardinality detection
        numeric_cols = []
        low_card_cats = []
        total_rows = len(X_raw)

        for col in X_raw.columns:
            num_s = pd.to_numeric(X_raw[col].replace(["Infinity", "infinity", "inf", "-inf", np.inf, -np.inf], np.nan), errors="coerce")
            if num_s.notna().mean() >= 0.3:
                X_raw[col] = num_s.astype(np.float32)
                numeric_cols.append(col)
            else:
                uc = X_raw[col].nunique(dropna=True)
                if uc > 30 or (uc / max(1, total_rows)) > 0.01:
                    X_raw.drop(columns=[col], inplace=True)
                else:
                    X_raw[col] = X_raw[col].astype(str).fillna("missing")
                    low_card_cats.append(col)

        valid_cols = [c for c in X_raw.columns if X_raw[c].isna().mean() < 0.85 and X_raw[c].nunique(dropna=True) > 1]
        X_raw = X_raw[valid_cols]

        numeric_cols = [c for c in valid_cols if c in numeric_cols]
        low_card_cats = [c for c in valid_cols if c in low_card_cats]

        # Preprocessor Pipeline
        preprocessor = ColumnTransformer(transformers=[
            ("num", Pipeline([("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler())]), numeric_cols),
            ("cat", Pipeline([("imputer", SimpleImputer(strategy="constant", fill_value="missing")), ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False))]), low_card_cats)
        ])

        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y_raw)
        class_names = [str(c) for c in label_encoder.classes_]

        class_counts = pd.Series(y_encoded).value_counts()
        can_stratify = bool((class_counts.min() >= 2) and (len(class_counts) > 1))

        X_train, X_test, y_train, y_test = train_test_split(
            X_raw, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded if can_stratify else None
        )

        X_train_proc = preprocessor.fit_transform(X_train).astype(np.float32)
        X_test_proc = preprocessor.transform(X_test).astype(np.float32)

        X_train_proc = np.nan_to_num(X_train_proc, nan=0.0, posinf=0.0, neginf=0.0)
        X_test_proc = np.nan_to_num(X_test_proc, nan=0.0, posinf=0.0, neginf=0.0)

        clf = RandomForestClassifier(n_estimators=n_estimators, random_state=42, class_weight="balanced", n_jobs=-1)
        clf.fit(X_train_proc, y_train)

        y_pred = clf.predict(X_test_proc)
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
        rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

        labels_range = list(range(len(class_names)))
        cm = confusion_matrix(y_test, y_pred, labels=labels_range).tolist()
        clf_rep = classification_report(y_test, y_pred, labels=labels_range, target_names=class_names, output_dict=True, zero_division=0)

        # Feature Importances
        feat_names = list(preprocessor.get_feature_names_out()) if hasattr(preprocessor, "get_feature_names_out") else valid_cols
        importances = []
        for fn, imp in sorted(zip(feat_names, clf.feature_importances_), key=lambda x: x[1], reverse=True)[:15]:
            importances.append({"feature": fn.replace("num__", "").replace("cat__", ""), "importance": round(float(imp), 4)})

        # Save artifacts
        joblib.dump(clf, version_dir / "model.joblib")
        joblib.dump(preprocessor, version_dir / "preprocessor.joblib")
        joblib.dump(label_encoder, version_dir / "label_encoder.joblib")
        joblib.dump(clf, model_dir / "model.joblib")
        joblib.dump(preprocessor, model_dir / "preprocessor.joblib")
        joblib.dump(label_encoder, model_dir / "label_encoder.joblib")

        metrics_payload = {
            "model_family": "network_threat",
            "version": version,
            "algorithm": "RandomForestClassifier",
            "classification_mode": classification_mode,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
            "classification_report": clf_rep,
            "top_features": importances,
            "classes": class_names,
            "total_records": len(combined_df),
            "training_records": len(X_train),
            "testing_records": len(X_test),
            "features_count": len(valid_cols)
        }

        with open(version_dir / "metrics.json", "w", encoding="utf-8") as fp:
            json.dump(metrics_payload, fp, indent=2)
        with open(model_dir / "metrics.json", "w", encoding="utf-8") as fp:
            json.dump(metrics_payload, fp, indent=2)

        schema_payload = {
            "model_family": "network_threat",
            "version": version,
            "numeric_features": numeric_cols,
            "categorical_features": low_card_cats,
            "classes": class_names
        }
        with open(version_dir / "feature_schema.json", "w", encoding="utf-8") as fp:
            json.dump(schema_payload, fp, indent=2)
        with open(model_dir / "feature_schema.json", "w", encoding="utf-8") as fp:
            json.dump(schema_payload, fp, indent=2)

        return metrics_payload

    @classmethod
    def evaluate_network_data(cls, df: pd.DataFrame, model_dir: Path) -> Dict[str, Any]:
        """
        Evaluates network CSV records against the active Network Threat Model.
        """
        model_path = model_dir / "model.joblib"
        prep_path = model_dir / "preprocessor.joblib"
        lbl_path = model_dir / "label_encoder.joblib"

        if not model_path.exists() or not prep_path.exists():
            return {
                "file_type": "NETWORK FLOW DATASET",
                "model_family": "Network Threat Model",
                "status": "NOT_TRAINED",
                "message": "NETWORK MODEL NOT TRAINED: Train the Network Threat Model first.",
                "total_records": len(df),
                "results": [],
                "summary": {"normal": 0, "suspicious": 0, "attack": 0, "critical": 0, "avg_risk_score": 0.0, "avg_confidence": 0.0, "top_sources": []}
            }

        clf = joblib.load(model_path)
        preprocessor = joblib.load(prep_path)
        label_encoder = joblib.load(lbl_path) if lbl_path.exists() else None

        df_eval = df.copy()
        df_eval.columns = [str(c).strip() for c in df_eval.columns]
        rename_map = {c: cls.canonicalize_column(c) for c in df_eval.columns}
        df_mapped = df_eval.rename(columns=rename_map)

        expected = list(preprocessor.feature_names_in_) if hasattr(preprocessor, "feature_names_in_") else []
        missing = [f for f in expected if f not in df_mapped.columns]

        if expected and (len(missing) / len(expected)) > 0.5:
            return {
                "file_type": "NETWORK FLOW DATASET",
                "model_family": "Network Threat Model",
                "status": "INCOMPATIBLE",
                "message": f"MODEL INCOMPATIBLE: Missing {len(missing)} of {len(expected)} required network flow features.",
                "missing_features": missing[:15],
                "expected_features": expected[:15],
                "total_records": len(df),
                "results": [],
                "summary": {"normal": 0, "suspicious": 0, "attack": 0, "critical": 0, "avg_risk_score": 0.0, "avg_confidence": 0.0, "top_sources": []}
            }

        for f in expected:
            if f not in df_mapped.columns:
                df_mapped[f] = 0.0

        X_eval = df_mapped[expected].copy() if expected else df_mapped.copy()
        X_eval.replace(["Infinity", "infinity", "inf", "-inf", np.inf, -np.inf], np.nan, inplace=True)
        for c in X_eval.columns:
            if X_eval[c].dtype == object:
                num_c = pd.to_numeric(X_eval[c], errors="coerce")
                if num_c.notna().mean() >= 0.5:
                    X_eval[c] = num_c.fillna(0.0).astype(np.float32)

        X_proc = preprocessor.transform(X_eval).astype(np.float32)
        X_proc = np.nan_to_num(X_proc, nan=0.0, posinf=0.0, neginf=0.0)

        preds = clf.predict(X_proc)
        probs = clf.predict_proba(X_proc) if hasattr(clf, "predict_proba") else np.ones((len(preds), 1))

        results = []
        threat_sources: Dict[str, Dict[str, Any]] = {}

        for idx, (p_idx, prob_row) in enumerate(zip(preds, probs)):
            conf = float(np.max(prob_row))
            label_str = str(label_encoder.inverse_transform([p_idx])[0]) if label_encoder else str(p_idx)
            is_attack = (label_str.lower() not in ["normal", "benign", "0"])

            dst_p = int(df_mapped.iloc[idx].get("dst_port", 80)) if "dst_port" in df_mapped.columns else 80
            src_p = int(df_mapped.iloc[idx].get("src_port", 50000)) if "src_port" in df_mapped.columns else 50000
            proto = str(df_mapped.iloc[idx].get("protocol", "TCP"))

            risk = int(88 * conf) if is_attack else int((1.0 - conf) * 20)
            if dst_p in [4444, 31337]: risk = max(risk, 95)
            sev = "CRITICAL" if risk >= 85 else ("HIGH" if risk >= 70 else ("MEDIUM" if is_attack else "LOW"))

            src_ip = str(df.iloc[idx].get("Source IP") or df.iloc[idx].get("src_ip") or df.iloc[idx].get("srcip") or "192.168.56.104")
            dst_ip = str(df.iloc[idx].get("Destination IP") or df.iloc[idx].get("dst_ip") or df.iloc[idx].get("dstip") or "192.168.56.107")

            if is_attack:
                if src_ip not in threat_sources:
                    threat_sources[src_ip] = {"source_ip": src_ip, "device": get_device_label(src_ip), "count": 0}
                threat_sources[src_ip]["count"] += 1

            results.append({
                "timestamp": str(df.iloc[idx].get("Timestamp") or df.iloc[idx].get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")),
                "alert_status": sev if is_attack else "NORMAL",
                "is_attack": is_attack,
                "attack_category": label_str if is_attack else "Normal Traffic",
                "prediction": label_str,
                "confidence": round(conf * 100, 1),
                "risk_score": risk,
                "severity_score": risk,
                "threat_level": sev,
                "source_ip": src_ip,
                "source_device": get_device_label(src_ip),
                "destination_ip": dst_ip,
                "destination_device": get_device_label(dst_ip),
                "protocol_details": {
                    "protocol": proto,
                    "src_port": src_p,
                    "dst_port": dst_p,
                    "flags": ""
                },
                "mitre_technique": get_mitre(label_str),
                "recommendation": "Quarantine Host & Block Port" if is_attack else "Log & Monitor Flow",
                "explanation": f"Network Model classified flow as {label_str} with {conf*100:.1f}% confidence.",
                "raw_attributes": {
                    str(k): (None if pd.isna(v) else (int(v) if isinstance(v, (np.integer, int)) else (float(v) if isinstance(v, (np.floating, float)) and not (np.isnan(v) or np.isinf(v)) else str(v))))
                    for k, v in df.iloc[idx].to_dict().items()
                }
            })

        total = len(results)
        top_sources = sorted(threat_sources.values(), key=lambda x: x["count"], reverse=True)[:5]

        return {
            "file_type": "NETWORK FLOW DATASET",
            "model_family": "Network Threat Model",
            "total_records": total,
            "status": "SUCCESS",
            "summary": {
                "normal": sum(1 for r in results if r["alert_status"] == "NORMAL"),
                "suspicious": sum(1 for r in results if r["alert_status"] == "SUSPICIOUS"),
                "attack": sum(1 for r in results if r["alert_status"] == "ATTACK"),
                "critical": sum(1 for r in results if r["alert_status"] == "CRITICAL"),
                "avg_risk_score": round(sum(r["risk_score"] for r in results) / max(1, total), 1),
                "avg_confidence": round(sum(r["confidence"] for r in results) / max(1, total), 1),
                "top_sources": top_sources
            },
            "results": results
        }
