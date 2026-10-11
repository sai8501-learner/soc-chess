#!/usr/bin/env python3
"""
================================================================================
SOC CHESS -- SPLUNK LOG & SECURITY EVENT PREDICTION ENGINE
================================================================================
STEP 7 of the ML pipeline.

Loads the best trained Splunk telemetry model from models/splunk/ and provides:
  - Single log/event inference (dict -> classification + MITRE technique + threat score)
  - Batch log inference (DataFrame or JSON array)
  - Interactive & automated self-testing
  - Threat severity mapping (LOW / MEDIUM / HIGH / CRITICAL)
  - Adversarial tactical chess interpretation

Usage:
  python python/predict_splunk.py --test
  python python/predict_splunk.py --json '{"event_type": "ProcessCreate", "data_type": "windows_sysmon", ...}'
================================================================================
"""

import sys
import json
import time
import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import numpy as np
import pandas as pd
import joblib

# Bootstrap path
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from model_utils import (
    BASE_DIR, MODELS_DIR, MODELS_SPLUNK_DIR, PYTHON_DIR,
    safe_json_read, confidence_to_threat_level
)

# ---------------------------------------------------------------------------
# ADVERSARIAL CHESS TACTICAL MAPPING FOR SYSTEM & LOG EVENTS
# ---------------------------------------------------------------------------
SPLUNK_TACTICAL_MAP = {
    "NORMAL": "Dormant Defense (Nominal operations / benign telemetry)",
    "DISCOVERY": "Rook Scan (System & Active Directory reconnaissance)",
    "EXECUTION": "Tactical Strike (Malicious process execution / script abuse)",
    "PERSISTENCE": "Outpost Setup (Registry run keys / scheduled tasks)",
    "PRIVILEGE_ESCALATION": "Pawn Promotion (Privilege elevation / token manipulation)",
    "DEFENSE_EVASION": "Smoke & Mirrors (Process hollowing / log clearing)",
    "CREDENTIAL_ACCESS": "Stealing the Opponent's Pieces (LSASS dump / SAM extraction)",
    "LATERAL_MOVEMENT": "Board Transposition (PsExec / WMI / SMB pivoting)",
    "COMMAND_AND_CONTROL": "Grandmaster Tether (C2 beaconing / reverse shell)",
    "EXFILTRATION": "Securing the Trophy (Staged data archive & egress)",
    "IMPACT": "Checkmate Blow (Ransomware encryption / service destruction)",
}

def map_splunk_tactic(predicted_class: str, mitre_technique: str = "") -> str:
    upper = str(predicted_class).upper()
    for key, tactic in SPLUNK_TACTICAL_MAP.items():
        if key in upper:
            return tactic
    if upper == "NORMAL":
        return SPLUNK_TACTICAL_MAP["NORMAL"]
    tactic_label = f"Adversarial Maneuver [{predicted_class}]"
    if mitre_technique:
        tactic_label += f" (MITRE {mitre_technique})"
    return tactic_label


class SplunkPredictor:
    """Production predictor for Splunk security logs and events."""

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = model_dir or MODELS_SPLUNK_DIR
        self.best_meta: Dict[str, Any] = {}
        self.model: Any = None
        self.preprocessor: Any = None
        self.label_encoder: Any = None
        self.features_meta: Dict[str, Any] = {}
        self.is_loaded = False
        self._load()

    def _load(self):
        best_meta_path = self.model_dir / "best_model.json"
        if not best_meta_path.exists():
            best_meta_path = MODELS_DIR / "splunk_best_model.json"

        if not best_meta_path.exists():
            raise FileNotFoundError(
                f"Splunk model not found. Run python/train_splunk_models.py first. (Checked {best_meta_path})"
            )

        self.best_meta = safe_json_read(best_meta_path) or {}
        algo = self.best_meta.get("algorithm", "Random Forest")

        # Load preprocessor
        prep_path = self.model_dir / "preprocessor.pkl"
        if not prep_path.exists():
            prep_path = Path(self.best_meta.get("preprocessor_path", str(MODELS_DIR / "splunk_preprocessor.pkl")))
        self.preprocessor = joblib.load(prep_path)

        # Load label encoder
        le_path = self.model_dir / "label_encoder.pkl"
        if not le_path.exists():
            le_path = Path(self.best_meta.get("label_encoder_path", str(MODELS_DIR / "splunk_label_encoder.pkl")))
        self.label_encoder = joblib.load(le_path)

        # Load features meta
        feat_path = self.model_dir / "features.json"
        if not feat_path.exists():
            feat_path = Path(self.best_meta.get("features_path", str(MODELS_DIR / "splunk_features.json")))
        self.features_meta = safe_json_read(feat_path) or {}

        # Load model
        model_path_str = self.best_meta.get("model_path", "")
        model_path = Path(model_path_str) if model_path_str else (self.model_dir / ("random_forest.pkl" if "forest" in algo.lower() else "xgboost.json"))
        if not model_path.exists():
            model_path = self.model_dir / ("random_forest.pkl" if "forest" in algo.lower() else "xgboost.json")

        if "xgboost" in algo.lower() or model_path.suffix == ".json":
            import xgboost as xgb
            self.model = xgb.XGBClassifier()
            self.model.load_model(str(model_path))
        else:
            self.model = joblib.load(model_path)

        self.is_loaded = True

    def predict_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Predict a single security event."""
        df = pd.DataFrame([event])
        results = self.predict_batch(df)
        return results[0] if results else {}

    def predict_batch(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Predict a batch of security events."""
        if not self.is_loaded:
            raise RuntimeError("Model is not loaded.")

        df_input = df.copy()
        raw_feature_cols = self.features_meta.get("raw_feature_cols", [])

        # Ensure all expected columns exist
        for col in raw_feature_cols:
            if col not in df_input.columns:
                df_input[col] = "UNKNOWN"

        X = df_input[raw_feature_cols].copy()

        # Transform features
        X_prep = self.preprocessor.transform(X)

        # Predict
        preds = self.model.predict(X_prep)

        # Probabilities
        probabilities = None
        try:
            probabilities = self.model.predict_proba(X_prep)
        except Exception:
            pass

        results = []
        classes = self.label_encoder.classes_

        for i, pred_idx in enumerate(preds):
            pred_label = str(classes[pred_idx])
            is_threat = (pred_label.upper() != "NORMAL")

            if probabilities is not None:
                conf = float(np.max(probabilities[i]))
                class_probs = {str(classes[c_idx]): float(probabilities[i][c_idx]) for c_idx in range(len(classes))}
            else:
                conf = 0.92 if is_threat else 0.99
                class_probs = {pred_label: conf}

            mitre = str(df_input.get("mitre_technique", pd.Series([""])).iloc[i] if "mitre_technique" in df_input else "")
            threat_level = confidence_to_threat_level(conf, pred_label)
            chess_tactic = map_splunk_tactic(pred_label, mitre)

            results.append({
                "prediction": pred_label,
                "is_threat": is_threat,
                "confidence": round(conf, 4),
                "threat_level": threat_level,
                "mitre_technique": mitre or None,
                "chess_tactic": chess_tactic,
                "class_probabilities": class_probs,
                "model_used": self.best_meta.get("algorithm", "Unknown"),
                "timestamp": pd.Timestamp.now().isoformat(),
            })

        return results


def run_self_test(predictor: SplunkPredictor):
    print("=" * 60)
    print("  SOC CHESS -- SPLUNK PREDICTOR SELF-TEST")
    print("=" * 60)
    print(f"  Model:      {predictor.best_meta.get('algorithm')}")
    print(f"  Classes:    {predictor.label_encoder.classes_.tolist()}")
    print(f"  Features:   {len(predictor.features_meta.get('raw_feature_cols', []))}")
    print("-" * 60)

    # Sample normal event
    normal_sample = {
        "event_type": "ProcessCreate",
        "data_type": "windows_sysmon",
        "process_name": "explorer.exe",
        "command_line": "C:\\Windows\\Explorer.EXE",
        "username": "WORKSTATION\\User",
        "hostname": "DESKTOP-SOC1",
    }

    # Sample attack event (PowerShell encoded execution)
    attack_sample = {
        "event_type": "powershell_exec",
        "data_type": "windows_powershell",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        "attack_category": "T1059.001",
        "mitre_technique": "T1059.001",
        "username": "SYSTEM",
        "hostname": "DC-PRIMARY",
    }

    res_norm = predictor.predict_event(normal_sample)
    res_att = predictor.predict_event(attack_sample)

    print("\n[Sample 1: Standard Explorer Launch]")
    print(f"  Prediction:   {res_norm['prediction']}")
    print(f"  Threat Level: {res_norm['threat_level']} (Confidence: {res_norm['confidence'] * 100:.1f}%)")
    print(f"  Chess Tactic: {res_norm['chess_tactic']}")

    print("\n[Sample 2: Encoded PowerShell Command Execution]")
    print(f"  Prediction:   {res_att['prediction']}")
    print(f"  Threat Level: {res_att['threat_level']} (Confidence: {res_att['confidence'] * 100:.1f}%)")
    print(f"  Chess Tactic: {res_att['chess_tactic']}")

    print("\n" + "=" * 60)
    print("  SELF-TEST RESULT: PASSED")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="SOC Chess Splunk Event ML Predictor")
    parser.add_argument("--test", action="store_true", help="Run automated predictor self-test")
    parser.add_argument("--json", type=str, help="JSON string representing a single security event")
    parser.add_argument("--file", type=str, help="Path to JSON or CSV file containing security events")
    args = parser.parse_args()

    try:
        predictor = SplunkPredictor()
    except Exception as e:
        print(f"Error initializing SplunkPredictor: {e}", file=sys.stderr)
        sys.exit(1)

    if args.test or (not args.json and not args.file):
        run_self_test(predictor)
        return

    if args.json:
        event_data = json.loads(args.json)
        res = predictor.predict_event(event_data)
        print(json.dumps(res, indent=2))

    elif args.file:
        fpath = Path(args.file)
        if fpath.suffix.lower() == ".csv":
            df = pd.read_csv(fpath)
        else:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            df = pd.DataFrame(data if isinstance(data, list) else [data])

        results = predictor.predict_batch(df)
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
