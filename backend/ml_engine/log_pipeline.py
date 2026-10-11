import os
import re
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

logger = logging.getLogger("socchess.ml.log_pipeline")

# Keywords for message-derived security indicators
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_REGEX = re.compile(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b')


class SecurityLogMLPipeline:
    """
    Dedicated ML Pipeline for Windows Security Events and Splunk Logs.
    Extracts compact security-relevant features without one-hot encoding raw messages or IDs.
    Supports Supervised RandomForest and Unsupervised IsolationForest Anomaly Detection.
    """

    @classmethod
    def extract_log_features(cls, df: pd.DataFrame) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
        """
        Extracts structured security indicators and separates raw investigation text.
        """
        features_df = pd.DataFrame(index=df.index)
        cols_lower = {str(c).strip().lower(): c for c in df.columns}

        # 1. Event Information
        for target_key, candidate_names in [
            ("EventCode", ["eventcode", "event_code", "eventid", "event_id"]),
            ("EventType", ["eventtype", "type"]),
            ("TaskCategory", ["taskcategory", "task_category", "task"]),
            ("LogName", ["logname", "log_name"]),
            ("SourceName", ["sourcename", "source_name", "provider_name"])
        ]:
            found_col = next((cols_lower[c] for c in candidate_names if c in cols_lower), None)
            if found_col:
                if target_key == "EventCode":
                    features_df["EventCode"] = pd.to_numeric(df[found_col], errors="coerce").fillna(0).astype(np.int32)
                else:
                    features_df[target_key] = df[found_col].astype(str).fillna("unknown")
            else:
                if target_key == "EventCode":
                    features_df["EventCode"] = 0
                else:
                    features_df[target_key] = "unknown"

        # 2. Account Information Indicators
        acc_col = next((cols_lower[c] for c in ["account_name", "user", "username", "account"] if c in cols_lower), None)
        if acc_col:
            acc_s = df[acc_col].astype(str).fillna("")
            features_df["is_system_account"] = acc_s.str.contains(r'SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$', regex=True, case=False).astype(np.int8)
            features_df["is_admin_account"] = acc_s.str.contains(r'Administrator|Admin|root', regex=True, case=False).astype(np.int8)
            features_df["account_name_len"] = acc_s.str.len().fillna(0).astype(np.int16)
        else:
            features_df["is_system_account"] = 0
            features_df["is_admin_account"] = 0
            features_df["account_name_len"] = 0

        dom_col = next((cols_lower[c] for c in ["account_domain", "domain", "group_domain"] if c in cols_lower), None)
        features_df["has_domain"] = 1 if dom_col else 0

        # 3. Process Information Indicators
        proc_col = next((cols_lower[c] for c in ["process_name", "processname", "image", "process"] if c in cols_lower), None)
        if proc_col:
            proc_s = df[proc_col].astype(str).fillna("")
            features_df["has_powershell"] = proc_s.str.contains("powershell", case=False).astype(np.int8)
            features_df["has_cmd"] = proc_s.str.contains(r'cmd\.exe|conhost', regex=True, case=False).astype(np.int8)
            features_df["is_suspicious_process"] = proc_s.str.contains(r'vssvc|whoami|net\.exe|nltest|rundll32|certutil|bitsadmin', regex=True, case=False).astype(np.int8)
        else:
            features_df["has_powershell"] = 0
            features_df["has_cmd"] = 0
            features_df["is_suspicious_process"] = 0

        # 4. Message-Derived Security Indicators (From Message / _raw)
        msg_col = next((cols_lower[c] for c in ["message", "_raw", "msg", "raw"] if c in cols_lower), None)
        if msg_col:
            msg_s = df[msg_col].astype(str).fillna("")
            features_df["msg_length"] = msg_s.str.len().fillna(0).astype(np.int32)
            features_df["msg_lines_count"] = msg_s.str.count("\n").fillna(0).astype(np.int16)
            features_df["msg_contains_ip"] = msg_s.str.contains(IP_REGEX).astype(np.int8)
            features_df["msg_contains_domain"] = msg_s.str.contains(DOMAIN_REGEX).astype(np.int8)
            features_df["msg_has_failed_auth"] = msg_s.str.contains(r'failed|failure|invalid|bad password|locked', regex=True, case=False).astype(np.int8)
            features_df["msg_has_success_auth"] = msg_s.str.contains(r'success|logged on|accepted', regex=True, case=False).astype(np.int8)
            features_df["msg_has_privilege"] = msg_s.str.contains(r'privilege|SeDebugPrivilege|SeTcbPrivilege|impersonate|token', regex=True, case=False).astype(np.int8)
            features_df["msg_has_group_mod"] = msg_s.str.contains(r'group|enumerat|member|added|removed|Security Group', regex=True, case=False).astype(np.int8)
            features_df["msg_has_service"] = msg_s.str.contains(r'service|daemon|driver|installed|state changed', regex=True, case=False).astype(np.int8)
        else:
            features_df["msg_length"] = 0
            features_df["msg_lines_count"] = 0
            features_df["msg_contains_ip"] = 0
            features_df["msg_contains_domain"] = 0
            features_df["msg_has_failed_auth"] = 0
            features_df["msg_has_success_auth"] = 0
            features_df["msg_has_privilege"] = 0
            features_df["msg_has_group_mod"] = 0
            features_df["msg_has_service"] = 0

        # 5. Temporal Indicators
        time_col = next((cols_lower[c] for c in ["_time", "timestamp", "time", "date"] if c in cols_lower), None)
        if time_col:
            try:
                dt_s = pd.to_datetime(df[time_col], errors="coerce")
                features_df["hour"] = dt_s.dt.hour.fillna(12).astype(np.int8)
                features_df["day_of_week"] = dt_s.dt.dayofweek.fillna(0).astype(np.int8)
            except Exception:
                features_df["hour"] = 12
                features_df["day_of_week"] = 0
        else:
            features_df["hour"] = 12
            features_df["day_of_week"] = 0

        # Store Raw Event Records separately for analyst investigation
        raw_records = []
        for idx in range(min(500, len(df))):
            row_dict = df.iloc[idx].to_dict()
            raw_records.append({
                "timestamp": str(row_dict.get("_time") or row_dict.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")),
                "EventCode": int(features_df.iloc[idx]["EventCode"]),
                "ComputerName": str(row_dict.get("ComputerName") or row_dict.get("host") or "WORKSTATION-01"),
                "Account_Name": str(row_dict.get("Account_Name") or row_dict.get("User") or "SYSTEM"),
                "Process_Name": str(row_dict.get("Process_Name") or "N/A"),
                "TaskCategory": str(row_dict.get("TaskCategory") or "System"),
                "SourceName": str(row_dict.get("SourceName") or "Microsoft-Windows-Security-Auditing"),
                "_raw": str(row_dict.get("_raw") or row_dict.get("Message") or ""),
                "Message": str(row_dict.get("Message") or row_dict.get("_raw") or "")
            })

        return features_df, raw_records

    @classmethod
    def train_windows_log_model(
        cls,
        labeled_dfs: List[Tuple[pd.DataFrame, str]],
        model_dir: Path,
        version: str = "LOG-RF-001",
        n_estimators: int = 150
    ) -> Dict[str, Any]:
        """
        Trains Supervised Random Forest for labeled log datasets, or Isolation Forest if unlabeled.
        """
        model_dir.mkdir(parents=True, exist_ok=True)
        version_dir = model_dir / version
        version_dir.mkdir(parents=True, exist_ok=True)

        feature_dfs = []
        target_series = []

        for df, target_col in labeled_dfs:
            if target_col in df.columns:
                feats, _ = cls.extract_log_features(df)
                feature_dfs.append(feats)
                target_series.append(df[target_col].astype(str))

        if not feature_dfs:
            raise ValueError("No valid Windows/Splunk log data available for training.")

        X_raw = pd.concat(feature_dfs, axis=0, ignore_index=True)
        y_raw = pd.concat(target_series, axis=0, ignore_index=True)

        numeric_cols = [c for c in X_raw.columns if X_raw[c].dtype in [np.int32, np.int16, np.int8, np.float32, np.float64, int, float]]
        categorical_cols = [c for c in X_raw.columns if c not in numeric_cols]

        preprocessor = ColumnTransformer(transformers=[
            ("num", Pipeline([("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler())]), numeric_cols),
            ("cat", Pipeline([("imputer", SimpleImputer(strategy="constant", fill_value="unknown")), ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False))]), categorical_cols)
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
        feat_names = list(preprocessor.get_feature_names_out()) if hasattr(preprocessor, "get_feature_names_out") else numeric_cols + categorical_cols
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
            "model_family": "windows_splunk_log",
            "version": version,
            "algorithm": "RandomForestClassifier",
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
            "classification_report": clf_rep,
            "top_features": importances,
            "classes": class_names,
            "total_records": len(X_raw),
            "training_records": len(X_train),
            "testing_records": len(X_test),
            "features_count": len(X_raw.columns)
        }

        with open(version_dir / "metrics.json", "w", encoding="utf-8") as fp:
            json.dump(metrics_payload, fp, indent=2)
        with open(model_dir / "metrics.json", "w", encoding="utf-8") as fp:
            json.dump(metrics_payload, fp, indent=2)

        schema_payload = {
            "model_family": "windows_splunk_log",
            "version": version,
            "numeric_features": numeric_cols,
            "categorical_features": categorical_cols,
            "classes": class_names
        }
        with open(version_dir / "feature_schema.json", "w", encoding="utf-8") as fp:
            json.dump(schema_payload, fp, indent=2)
        with open(model_dir / "feature_schema.json", "w", encoding="utf-8") as fp:
            json.dump(schema_payload, fp, indent=2)

        return metrics_payload

    @classmethod
    def evaluate_log_data(
        cls,
        df: pd.DataFrame,
        model_dir: Path
    ) -> Dict[str, Any]:
        """
        Evaluates Windows Security / Splunk CSV logs against the active Windows Log Model.
        """
        model_path = model_dir / "model.joblib"
        prep_path = model_dir / "preprocessor.joblib"
        lbl_path = model_dir / "label_encoder.joblib"

        features_df, raw_records = cls.extract_log_features(df)

        if not model_path.exists() or not prep_path.exists():
            # Use Unsupervised Isolation Forest if no supervised model exists
            iso = IsolationForest(contamination=0.08, random_state=42)
            num_df = features_df.select_dtypes(include=[np.number]).fillna(0)
            preds_iso = iso.fit_predict(num_df)
            scores = iso.decision_function(num_df)

            results = []
            for idx in range(min(len(df), len(raw_records))):
                raw = raw_records[idx]
                is_anom = (preds_iso[idx] == -1)
                conf = round(float(np.clip(abs(scores[idx]) * 150 + 50, 50, 99)), 1)
                risk = int(conf if is_anom else (100 - conf) * 0.3)
                sev = "HIGH" if is_anom and risk > 75 else ("MEDIUM" if is_anom else "LOW")
                status_str = "ATTACK" if is_anom and risk > 75 else ("SUSPICIOUS" if is_anom else "NORMAL")

                results.append({
                    "timestamp": raw["timestamp"],
                    "alert_status": status_str,
                    "is_attack": is_anom,
                    "attack_category": "Log Anomaly (Unsupervised)" if is_anom else "Normal Event",
                    "prediction": status_str,
                    "confidence": conf,
                    "risk_score": risk,
                    "severity_score": risk,
                    "threat_level": sev,
                    "source_ip": "127.0.0.1",
                    "source_device": raw["ComputerName"],
                    "destination_ip": "127.0.0.1",
                    "destination_device": raw["Account_Name"],
                    "protocol_details": {
                        "protocol": "EVENT",
                        "src_port": int(raw["EventCode"]),
                        "dst_port": int(raw["EventCode"]),
                        "flags": raw["TaskCategory"]
                    },
                    "mitre_technique": "T1078 - Valid Accounts / Anomaly",
                    "recommendation": "Investigate Security Event & User Privileges" if is_anom else "Audit & Retain Log",
                    "explanation": f"Evaluated via Log Anomaly Isolation Forest. EventCode: {raw['EventCode']} | Task: {raw['TaskCategory']} | Account: {raw['Account_Name']}",
                    "raw_attributes": raw
                })

            total = len(results)
            return {
                "file_type": "SPLUNK / WINDOWS SECURITY LOG",
                "model_family": "Windows/Splunk Log Model (Isolation Forest)",
                "total_records": total,
                "status": "SUCCESS",
                "summary": {
                    "normal": sum(1 for r in results if r["alert_status"] == "NORMAL"),
                    "suspicious": sum(1 for r in results if r["alert_status"] == "SUSPICIOUS"),
                    "attack": sum(1 for r in results if r["alert_status"] == "ATTACK"),
                    "critical": sum(1 for r in results if r["alert_status"] == "CRITICAL"),
                    "avg_risk_score": round(sum(r["risk_score"] for r in results) / max(1, total), 1),
                    "avg_confidence": round(sum(r["confidence"] for r in results) / max(1, total), 1),
                    "top_sources": []
                },
                "results": results
            }

        # Supervised Model Inference
        clf = joblib.load(model_path)
        preprocessor = joblib.load(prep_path)
        label_encoder = joblib.load(lbl_path) if lbl_path.exists() else None

        X_proc = preprocessor.transform(features_df).astype(np.float32)
        preds = clf.predict(X_proc)
        probs = clf.predict_proba(X_proc) if hasattr(clf, "predict_proba") else np.ones((len(preds), 1))

        results = []
        for idx in range(min(len(df), len(raw_records))):
            raw = raw_records[idx]
            p_idx = preds[idx]
            conf = float(np.max(probs[idx]))
            label_str = str(label_encoder.inverse_transform([p_idx])[0]) if label_encoder else str(p_idx)
            is_attack = (label_str.lower() not in ["normal", "benign", "0"])

            risk = int(85 * conf) if is_attack else int((1.0 - conf) * 20)
            sev = "CRITICAL" if risk >= 80 else ("HIGH" if risk >= 65 else ("MEDIUM" if is_attack else "LOW"))

            results.append({
                "timestamp": raw["timestamp"],
                "alert_status": sev if is_attack else "NORMAL",
                "is_attack": is_attack,
                "attack_category": label_str if is_attack else "Normal Traffic",
                "prediction": label_str,
                "confidence": round(conf * 100, 1),
                "risk_score": risk,
                "severity_score": risk,
                "threat_level": sev,
                "source_ip": "127.0.0.1",
                "source_device": raw["ComputerName"],
                "destination_ip": "127.0.0.1",
                "destination_device": raw["Account_Name"],
                "protocol_details": {
                    "protocol": "EVENT",
                    "src_port": int(raw["EventCode"]),
                    "dst_port": int(raw["EventCode"]),
                    "flags": raw["TaskCategory"]
                },
                "mitre_technique": "T1078 - Valid Accounts" if is_attack else "N/A",
                "recommendation": "Quarantine Account & Audit Privileges" if is_attack else "Audit Log Retained",
                "explanation": f"Classified by Windows Log Model as {label_str} with {conf*100:.1f}% confidence. EventCode: {raw['EventCode']} | Task: {raw['TaskCategory']}",
                "raw_attributes": raw
            })

        total = len(results)
        return {
            "file_type": "SPLUNK / WINDOWS SECURITY LOG",
            "model_family": "Windows/Splunk Log Model (Random Forest)",
            "total_records": total,
            "status": "SUCCESS",
            "summary": {
                "normal": sum(1 for r in results if r["alert_status"] == "NORMAL"),
                "suspicious": sum(1 for r in results if r["alert_status"] == "SUSPICIOUS"),
                "attack": sum(1 for r in results if r["alert_status"] == "ATTACK"),
                "critical": sum(1 for r in results if r["alert_status"] == "CRITICAL"),
                "avg_risk_score": round(sum(r["risk_score"] for r in results) / max(1, total), 1),
                "avg_confidence": round(sum(r["confidence"] for r in results) / max(1, total), 1),
                "top_sources": []
            },
            "results": results
        }
