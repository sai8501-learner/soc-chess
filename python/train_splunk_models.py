#!/usr/bin/env python3
"""
================================================================================
SOC CHESS -- SPLUNK MODEL TRAINING
================================================================================
STEP 5 of the ML pipeline.

Trains two models on splunk_merged.csv preprocessed data:
  1. Random Forest  -> models/splunk_random_forest.pkl
  2. XGBoost        -> models/splunk_xgboost.json

Evaluates both on the held-out test set.
Selects the best model by macro F1.
Saves metric files, comparison, and best_model.json.
Performs a load test on both saved models.

NOTE: If Splunk .log files are Git LFS pointers (not downloaded),
the dataset will be small (YAML metadata only). The system still
trains with whatever real data is available and logs the caveat.

Run:
  python python/train_splunk_models.py
================================================================================
"""

import sys, time, json, warnings, datetime
import numpy  as np
import pandas as pd
from pathlib import Path

warnings.filterwarnings("ignore")

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from model_utils import (
    PROCESSED_DIR, MODELS_DIR, PYTHON_DIR,
    setup_logger, safe_json_write, safe_json_read,
    compute_metrics, build_model_metadata,
    print_section, print_subsection,
)

import joblib
from sklearn.ensemble import RandomForestClassifier

log = setup_logger("train_splunk", PYTHON_DIR / "ml_training.log")

RANDOM_STATE = 42
PREFIX       = "splunk"

# ---------------------------------------------------------------------------
def load_data() -> tuple:
    log.info("Loading Splunk preprocessed data...")
    X_train = np.load(PROCESSED_DIR / f"{PREFIX}_X_train.npy", allow_pickle=True)
    X_test  = np.load(PROCESSED_DIR / f"{PREFIX}_X_test.npy",  allow_pickle=True)
    y_train = np.load(PROCESSED_DIR / f"{PREFIX}_y_train.npy", allow_pickle=True)
    y_test  = np.load(PROCESSED_DIR / f"{PREFIX}_y_test.npy",  allow_pickle=True)
    feat_meta_path = MODELS_DIR / "splunk" / "features.json"
    if not feat_meta_path.exists():
        feat_meta_path = MODELS_DIR / f"{PREFIX}_features.json"
    feat_meta = safe_json_read(feat_meta_path) or {}

    le_path = MODELS_DIR / "splunk" / "label_encoder.pkl"
    if not le_path.exists():
        le_path = MODELS_DIR / f"{PREFIX}_label_encoder.pkl"
    le = joblib.load(le_path)
    print(f"  Train: {X_train.shape}   Test: {X_test.shape}")
    print(f"  Classes: {le.classes_.tolist()}")
    log.info(f"Data loaded. Train={X_train.shape}  Test={X_test.shape}")

    if X_train.shape[0] < 20:
        log.warning("Very small Splunk dataset. LFS logs not downloaded. "
                    "Run 'git lfs pull' in datasets/Splunk-Attack-Data for full dataset.")
        print("\n  NOTE: Small dataset - Splunk .log files are Git LFS pointers.")
        print("  Run: cd datasets/Splunk-Attack-Data && git lfs pull")
        print("  Then re-run dataset_processor.py and prepare_ml_data.py.")

    return X_train, X_test, y_train, y_test, feat_meta, le

# ---------------------------------------------------------------------------
def train_random_forest(X_train, y_train, n_classes: int):
    print_subsection("Training Random Forest")
    log.info("Training Splunk Random Forest...")
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=0,
    )
    rf.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"  Training complete in {elapsed:.1f}s")
    log.info(f"Splunk RF trained in {elapsed:.1f}s")
    return rf

# ---------------------------------------------------------------------------
def train_xgboost(X_train, y_train, n_classes: int):
    print_subsection("Training XGBoost")
    log.info("Training Splunk XGBoost...")
    try:
        import xgboost as xgb
    except ImportError:
        log.error("XGBoost not installed. Run: pip install xgboost")
        raise

    t0 = time.time()
    params = dict(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=RANDOM_STATE,
        use_label_encoder=False,
        n_jobs=-1,
        verbosity=0,
    )
    if n_classes > 2:
        params["objective"]   = "multi:softprob"
        params["num_class"]   = n_classes
        params["eval_metric"] = "mlogloss"
    else:
        params["objective"]   = "binary:logistic"
        params["eval_metric"] = "logloss"

    xgb_model = xgb.XGBClassifier(**params)
    xgb_model.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"  Training complete in {elapsed:.1f}s")
    log.info(f"Splunk XGBoost trained in {elapsed:.1f}s")
    return xgb_model

# ---------------------------------------------------------------------------
def evaluate_and_save(
    model, model_name: str, save_path: Path,
    X_test, y_test, le, feat_meta: dict,
    X_train_len: int, use_json: bool = False
) -> dict:
    print(f"\n  Evaluating {model_name}...")
    y_pred = model.predict(X_test)
    metrics = compute_metrics(y_test, y_pred, le)

    print(f"    Accuracy:    {metrics['accuracy']:.4f}")
    print(f"    Macro F1:    {metrics['macro_f1']:.4f}")
    print(f"    Weighted F1: {metrics['weighted_f1']:.4f}")
    print(f"    Recall:      {metrics['recall']:.4f}")
    log.info(f"Splunk {model_name} | acc={metrics['accuracy']:.4f} macro_f1={metrics['macro_f1']:.4f}")

    save_path.parent.mkdir(parents=True, exist_ok=True)
    if use_json:
        model.save_model(str(save_path))
    else:
        joblib.dump(model, save_path)
    print(f"  Saved: {save_path}")

    n_features = feat_meta.get("n_processed_features", X_test.shape[1])
    classes    = le.classes_.tolist()

    full_metrics = {
        "model":        model_name,
        "dataset":      "splunk_merged.csv",
        "pipeline":     "splunk",
        "training_date": datetime.datetime.now().isoformat(),
        "training_records": int(X_train_len),
        "testing_records":  int(len(X_test)),
        "number_of_features": int(n_features),
        "number_of_classes":  int(len(classes)),
        "classes":    classes,
        **{k: v for k, v in metrics.items() if k not in ("classification_report","confusion_matrix")},
        "classification_report": metrics.get("classification_report",""),
        "confusion_matrix":      metrics.get("confusion_matrix",[]),
    }
    slug = model_name.lower().replace(" ","_")
    metrics_path = save_path.parent / f"{slug}_metrics.json"
    safe_json_write(full_metrics, metrics_path)
    print(f"  Metrics saved: {metrics_path}")
    return metrics

# ---------------------------------------------------------------------------
def load_test(rf_path: Path, xgb_path: Path, X_test, y_test, le) -> None:
    print_subsection("Load Test")
    sample = X_test[:5]

    try:
        rf_loaded = joblib.load(rf_path)
        preds     = rf_loaded.predict(sample)
        labels    = le.inverse_transform(preds)
        print(f"  Random Forest load test: OK  Predictions: {labels.tolist()}")
        log.info(f"Splunk RF load test PASSED. Predictions: {labels.tolist()}")
    except Exception as e:
        log.error(f"Splunk RF load test FAILED: {e}")
        print(f"  Random Forest load test FAILED: {e}")

    try:
        import xgboost as xgb
        xgb_loaded = xgb.XGBClassifier()
        xgb_loaded.load_model(str(xgb_path))
        preds  = xgb_loaded.predict(sample)
        labels = le.inverse_transform(preds)
        print(f"  XGBoost load test: OK  Predictions: {labels.tolist()}")
        log.info(f"Splunk XGB load test PASSED. Predictions: {labels.tolist()}")
    except Exception as e:
        log.error(f"Splunk XGB load test FAILED: {e}")
        print(f"  XGBoost load test FAILED: {e}")

# ---------------------------------------------------------------------------
def main():
    print_section("SOC CHESS -- SPLUNK MODEL TRAINING")
    t_start = time.time()

    target_dir = MODELS_DIR / "splunk"
    target_dir.mkdir(parents=True, exist_ok=True)

    req_files = [
        PROCESSED_DIR / f"{PREFIX}_X_train.npy",
        PROCESSED_DIR / f"{PREFIX}_y_train.npy",
    ]
    for f in req_files:
        if not f.exists():
            print(f"\n  ERROR: Required file not found: {f}")
            print("  Run prepare_ml_data.py first.")
            sys.exit(1)

    X_train, X_test, y_train, y_test, feat_meta, le = load_data()
    n_classes = len(le.classes_)

    # ---- Random Forest ----
    rf = train_random_forest(X_train, y_train, n_classes)
    rf_path    = target_dir / "random_forest.pkl"
    rf_metrics = evaluate_and_save(
        rf, "Random Forest", rf_path,
        X_test, y_test, le, feat_meta, len(X_train)
    )

    # ---- XGBoost ----
    xgb_path = target_dir / "xgboost.json"
    try:
        xgb_model   = train_xgboost(X_train, y_train, n_classes)
        xgb_metrics = evaluate_and_save(
            xgb_model, "XGBoost", xgb_path,
            X_test, y_test, le, feat_meta, len(X_train),
            use_json=True
        )
    except Exception as e:
        log.error(f"Splunk XGBoost training failed: {e}")
        print(f"\n  XGBoost FAILED: {e}")
        xgb_metrics = {"macro_f1":-1,"accuracy":0,"recall":0,"precision":0,"weighted_f1":0}

    # ---- Comparison ----
    comparison = {
        "pipeline":   "splunk",
        "dataset":    "splunk_merged.csv",
        "comparison_date": datetime.datetime.now().isoformat(),
        "Random Forest": {k: rf_metrics[k]  for k in ("accuracy","precision","recall","macro_f1","weighted_f1")},
        "XGBoost":       {k: xgb_metrics[k] for k in ("accuracy","precision","recall","macro_f1","weighted_f1")},
    }
    safe_json_write(comparison, target_dir / "comparison.json")

    # ---- Best model ----
    rf_score  = (rf_metrics["macro_f1"],  rf_metrics["recall"])
    xgb_score = (xgb_metrics["macro_f1"], xgb_metrics["recall"])

    if rf_score >= xgb_score:
        best_algo = "Random Forest"
        best_path = rf_path
        best_met  = rf_metrics
    else:
        best_algo = "XGBoost"
        best_path = xgb_path
        best_met  = xgb_metrics

    best_meta = {
        "pipeline":              "splunk",
        "algorithm":             best_algo,
        "model_path":            str(best_path),
        "preprocessor_path":     str(target_dir / "preprocessor.pkl"),
        "label_encoder_path":    str(target_dir / "label_encoder.pkl"),
        "features_path":         str(target_dir / "features.json"),
        "dataset":               "splunk_merged.csv",
        "training_date":         datetime.datetime.now().isoformat(),
        "number_of_records":     int(len(X_train) + len(X_test)),
        "number_of_features":    int(feat_meta.get("n_processed_features", X_test.shape[1])),
        "classes":               le.classes_.tolist(),
        "metrics":               {k: v for k, v in best_met.items()
                                  if k not in ("classification_report","confusion_matrix")},
        "note": "Splunk .log files are Git LFS pointers. Run 'git lfs pull' in "
                "datasets/Splunk-Attack-Data to get full Windows event logs for richer training.",
    }
    safe_json_write(best_meta, target_dir / "best_model.json")

    # ---- Load test ----
    load_test(rf_path, xgb_path, X_test, y_test, le)

    # ---- Summary ----
    elapsed = time.time() - t_start
    print("\n")
    print("=" * 60)
    print("  SOC CHESS ML TRAINING COMPLETE -- SPLUNK")
    print("=" * 60)
    print(f"\n  Dataset:  splunk_merged.csv")
    print(f"  Records:  {len(X_train)+len(X_test):,}")
    print(f"  Features: {feat_meta.get('n_processed_features','?')}")
    print(f"  Classes:  {le.classes_.tolist()}")
    print(f"\n  RANDOM FOREST")
    print(f"    Accuracy:    {rf_metrics['accuracy']:.4f}")
    print(f"    Precision:   {rf_metrics['precision']:.4f}")
    print(f"    Recall:      {rf_metrics['recall']:.4f}")
    print(f"    Macro F1:    {rf_metrics['macro_f1']:.4f}")
    print(f"    Weighted F1: {rf_metrics['weighted_f1']:.4f}")
    print(f"\n  XGBOOST")
    print(f"    Accuracy:    {xgb_metrics['accuracy']:.4f}")
    print(f"    Precision:   {xgb_metrics['precision']:.4f}")
    print(f"    Recall:      {xgb_metrics['recall']:.4f}")
    print(f"    Macro F1:    {xgb_metrics['macro_f1']:.4f}")
    print(f"    Weighted F1: {xgb_metrics['weighted_f1']:.4f}")
    print(f"\n  BEST SPLUNK MODEL: {best_algo}")
    print(f"  Elapsed: {elapsed:.1f}s")
    print("=" * 60)

    log.info(f"Splunk training complete. Best: {best_algo} | macro_f1={best_met['macro_f1']:.4f}")

if __name__ == "__main__":
    main()
