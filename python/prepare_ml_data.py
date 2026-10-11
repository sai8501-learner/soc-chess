#!/usr/bin/env python3
"""
================================================================================
SOC CHESS -- ML DATA PREPARATION
================================================================================
STEP 3 of the ML pipeline.

Loads network_merged.csv and splunk_merged.csv independently.
For each dataset:
  1. Drop leakage / non-feature columns
  2. Drop near-zero-variance columns
  3. Impute missing values
  4. Encode categorical variables
  5. Scale numeric features (fit ONLY on train split)
  6. Encode target labels with LabelEncoder
  7. Stratified 80/20 train/test split (random_state=42)
  8. Save preprocessed arrays + preprocessor + label encoder + feature list

Run:
  python python/prepare_ml_data.py
================================================================================
"""

import sys, json, time, warnings
import numpy  as np
import pandas as pd
from pathlib import Path

warnings.filterwarnings("ignore")

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from model_utils import (
    BASE_DIR, PROCESSED_DIR, MODELS_DIR, TRAINING_LOG, PYTHON_DIR,
    setup_logger, safe_json_write, print_section, print_subsection,
)

import joblib
from sklearn.model_selection  import train_test_split
from sklearn.preprocessing    import StandardScaler, LabelEncoder
from sklearn.impute            import SimpleImputer
from sklearn.pipeline          import Pipeline
from sklearn.compose           import ColumnTransformer
from sklearn.preprocessing     import OneHotEncoder

log = setup_logger("prepare_ml_data", PYTHON_DIR / "ml_training.log")

RANDOM_STATE = 42
TEST_SIZE    = 0.20

# Columns that must never be ML features
LEAKAGE_COLS = {
    "source_file","relative_path","absolute_path","source_dataset","data_type",
    "raw_message","attack_scenario","description","author","environment",
    "log_sourcetype","log_source","original_label","timestamp","date",
    "source_ip","destination_ip"
}
TARGET_COL = "label"

# Max unique values for categorical one-hot encoding
MAX_OHE_CARDINALITY = 50

# ---------------------------------------------------------------------------
def load_and_clean(csv_path: Path, pipeline_name: str) -> pd.DataFrame:
    """Load merged CSV and perform basic cleaning."""
    log.info(f"[{pipeline_name}] Loading: {csv_path}")
    print(f"\n  Loading: {csv_path.name}")

    if not csv_path.exists():
        raise FileNotFoundError(f"Merged CSV not found: {csv_path}. Run dataset_processor.py first.")

    df = pd.read_csv(csv_path, encoding="utf-8", low_memory=False)
    log.info(f"[{pipeline_name}] Loaded {len(df):,} rows, {len(df.columns)} columns")
    print(f"  Rows: {len(df):,}   Columns: {len(df.columns)}")

    if df.empty:
        raise ValueError(f"Dataset is empty: {csv_path}")

    # Drop all-null columns
    null_cols = [c for c in df.columns if df[c].isnull().all()]
    if null_cols:
        df = df.drop(columns=null_cols)
        log.info(f"[{pipeline_name}] Dropped {len(null_cols)} all-null columns")

    # Coerce known numeric features and sanitize infinite / extreme values
    for col in df.columns:
        if col not in LEAKAGE_COLS and col not in (TARGET_COL, "attack_category", "state", "service", "username", "hostname", "process_name", "event_type"):
            try:
                converted = pd.to_numeric(df[col], errors="coerce")
                if not converted.isna().all():
                    df[col] = converted
            except Exception:
                pass

    # Replace inf and -inf with NaN so SimpleImputer handles them
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Clip extreme numerical outliers
    num_cols = df.select_dtypes(include=[np.number]).columns
    for c in num_cols:
        df[c] = df[c].clip(-1e9, 1e9)

    return df

# ---------------------------------------------------------------------------
def select_features(df: pd.DataFrame, pipeline_name: str):
    """
    Separate features (X) from target (y).
    Drops leakage columns and low-variance columns.
    Returns X (DataFrame), y (Series), feature_names (list), actual_target_col (str).
    """
    target_col = TARGET_COL

    # For Splunk, if label has only 1 class, use attack_category for classification
    if pipeline_name.lower() == "splunk" and df[TARGET_COL].nunique() <= 1:
        if "attack_category" in df.columns and df["attack_category"].nunique() > 1:
            target_col = "attack_category"
            log.info(f"[{pipeline_name}] Using '{target_col}' as target for multi-class classification")

    if target_col not in df.columns:
        raise ValueError(f"Target column '{target_col}' not found. Columns: {df.columns.tolist()}")

    # Remove rows where target is null or UNKNOWN
    before = len(df)
    df = df[df[target_col].notna()]
    df = df[df[target_col].astype(str).str.upper() != "UNKNOWN"]
    df = df[df[target_col].astype(str).str.strip() != ""]
    log.info(f"[{pipeline_name}] Removed {before - len(df)} rows with unknown/null labels. Remaining: {len(df):,}")
    print(f"  After label filter: {len(df):,} rows")

    if len(df) < 10:
        raise ValueError(f"Insufficient labeled data ({len(df)} rows) for training.")

    # Check class balance
    class_counts = df[target_col].value_counts()
    # Filter out singleton classes if too small for splitting
    valid_classes = class_counts[class_counts >= 2].index
    if len(valid_classes) < len(class_counts):
        df = df[df[target_col].isin(valid_classes)]
        class_counts = df[target_col].value_counts()

    log.info(f"[{pipeline_name}] Class distribution:\n{class_counts.to_string()}")
    print(f"\n  Class distribution (Top 10):")
    for cls, cnt in class_counts.head(10).items():
        print(f"    {cls}: {cnt:,}")

    # Separate X and y
    drop_cols = LEAKAGE_COLS | {TARGET_COL, "attack_category", target_col}
    feature_cols = [c for c in df.columns if c not in drop_cols]

    # Drop near-constant columns
    low_var = []
    for col in feature_cols:
        if df[col].nunique(dropna=True) <= 1:
            low_var.append(col)
    if low_var:
        feature_cols = [c for c in feature_cols if c not in low_var]
        log.info(f"[{pipeline_name}] Dropped {len(low_var)} near-constant columns")

    X = df[feature_cols].copy()
    y = df[target_col].copy()

    log.info(f"[{pipeline_name}] Feature count: {len(feature_cols)}")
    print(f"\n  Features selected: {len(feature_cols)}")
    return X, y, feature_cols, target_col

# ---------------------------------------------------------------------------
def build_preprocessor(X_train: pd.DataFrame) -> ColumnTransformer:
    """
    Build a ColumnTransformer fitted ONLY on training data.
    Numeric columns: impute median -> scale.
    Categorical columns: impute 'UNKNOWN' -> OHE (if low cardinality) else drop.
    """
    numeric_cols     = X_train.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = X_train.select_dtypes(exclude=[np.number]).columns.tolist()

    # Split categoricals by cardinality
    ohe_cols  = [c for c in categorical_cols if X_train[c].nunique() <= MAX_OHE_CARDINALITY]
    drop_cats = [c for c in categorical_cols if X_train[c].nunique() > MAX_OHE_CARDINALITY]

    if drop_cats:
        log.info(f"  Dropping {len(drop_cats)} high-cardinality categoricals: {drop_cats[:5]}...")

    transformers = []
    if numeric_cols:
        num_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler",  StandardScaler()),
        ])
        transformers.append(("num", num_pipe, numeric_cols))

    if ohe_cols:
        cat_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="constant", fill_value="UNKNOWN")),
            ("ohe",     OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ])
        transformers.append(("cat", cat_pipe, ohe_cols))

    if not transformers:
        # Fallback: treat as categorical UNKNOWN
        cat_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="constant", fill_value="UNKNOWN")),
            ("ohe",     OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ])
        transformers.append(("cat_fallback", cat_pipe, X_train.columns.tolist()))

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")
    return preprocessor

# ---------------------------------------------------------------------------
def get_feature_names_out(preprocessor: ColumnTransformer, X: pd.DataFrame) -> list:
    """Extract final feature names from a fitted ColumnTransformer."""
    feature_names = []
    for name, trans, cols in preprocessor.transformers_:
        if name == "remainder":
            continue
        if hasattr(trans, "get_feature_names_out"):
            try:
                names = trans.get_feature_names_out()
                feature_names.extend(names)
                continue
            except Exception:
                pass
        if hasattr(trans, "named_steps"):
            last = list(trans.named_steps.values())[-1]
            if hasattr(last, "get_feature_names_out"):
                try:
                    names = last.get_feature_names_out()
                    feature_names.extend(names)
                    continue
                except Exception:
                    pass
        feature_names.extend(cols if isinstance(cols, list) else [cols])
    return feature_names

# ---------------------------------------------------------------------------
def prepare_pipeline(pipeline_name: str, csv_path: Path, prefix: str) -> dict:
    """Full preparation pipeline for one dataset. Returns metadata dict."""
    print_section(f"PREPARING: {pipeline_name.upper()}")
    t0 = time.time()

    # 1. Load
    df = load_and_clean(csv_path, pipeline_name)

    # 2. Feature selection
    X, y, feature_cols, target_col = select_features(df, pipeline_name)

    # 3. Train/test split (stratified when possible)
    print(f"\n  Splitting: 80% train / 20% test  (random_state={RANDOM_STATE})")
    try:
        X_train, X_test, y_train_raw, y_test_raw = train_test_split(
            X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
        )
    except ValueError:
        log.warning(f"[{pipeline_name}] Stratified split failed, using random split")
        X_train, X_test, y_train_raw, y_test_raw = train_test_split(
            X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
        )
    print(f"  Train: {len(X_train):,}   Test: {len(X_test):,}")

    # 4. Label encoding (fit on train labels only)
    le = LabelEncoder()
    y_train = le.fit_transform(y_train_raw.astype(str))
    y_test  = le.transform(y_test_raw.astype(str))
    classes = le.classes_.tolist()
    print(f"  Classes: {classes}")
    log.info(f"[{pipeline_name}] Classes: {classes}")

    # 5. Build preprocessor (fit on train only)
    print_subsection("Building preprocessor (fit on train only)")
    preprocessor = build_preprocessor(X_train)
    X_train_prep = preprocessor.fit_transform(X_train)
    X_test_prep  = preprocessor.transform(X_test)

    final_feature_names = get_feature_names_out(preprocessor, X_train)
    n_features = X_train_prep.shape[1]
    print(f"  Preprocessed features: {n_features}")
    log.info(f"[{pipeline_name}] Preprocessed shape: {X_train_prep.shape}")

    # 6. Save preprocessed data arrays
    np.save(PROCESSED_DIR / f"{prefix}_X_train.npy", X_train_prep)
    np.save(PROCESSED_DIR / f"{prefix}_X_test.npy",  X_test_prep)
    np.save(PROCESSED_DIR / f"{prefix}_y_train.npy", y_train)
    np.save(PROCESSED_DIR / f"{prefix}_y_test.npy",  y_test)
    log.info(f"[{pipeline_name}] Saved preprocessed arrays")

    # 7. Save preprocessor
    target_models_dir = MODELS_DIR / prefix
    target_models_dir.mkdir(parents=True, exist_ok=True)
    preprocessor_path = target_models_dir / "preprocessor.pkl"
    joblib.dump(preprocessor, preprocessor_path)
    log.info(f"[{pipeline_name}] Preprocessor saved: {preprocessor_path}")
    print(f"  Preprocessor saved: {preprocessor_path}")

    # 8. Save label encoder
    le_path = target_models_dir / "label_encoder.pkl"
    joblib.dump(le, le_path)
    log.info(f"[{pipeline_name}] Label encoder saved: {le_path}")
    print(f"  Label encoder saved: {le_path}")

    # 9. Save feature list
    features_data = {
        "pipeline":          pipeline_name,
        "prefix":            prefix,
        "raw_feature_cols":  feature_cols,
        "processed_features": final_feature_names,
        "n_raw_features":    len(feature_cols),
        "n_processed_features": n_features,
        "classes":           classes,
        "n_classes":         len(classes),
        "n_train":           int(len(X_train)),
        "n_test":            int(len(X_test)),
        "target_col":        TARGET_COL,
    }
    features_path = target_models_dir / "features.json"
    safe_json_write(features_data, features_path)
    print(f"  Features saved: {features_path}")

    elapsed = time.time() - t0
    print(f"\n  Done in {elapsed:.1f}s")
    log.info(f"[{pipeline_name}] Preparation complete in {elapsed:.1f}s")

    return features_data

# ---------------------------------------------------------------------------
def main():
    print_section("SOC CHESS ML DATA PREPARATION")
    t_start = time.time()

    results = {}

    # Network pipeline
    net_csv = PROCESSED_DIR / "network_merged.csv"
    if net_csv.exists() and net_csv.stat().st_size > 100:
        try:
            results["network"] = prepare_pipeline("Network", net_csv, "network")
        except Exception as e:
            log.error(f"Network preparation failed: {e}")
            print(f"\n  ERROR (Network): {e}")
    else:
        print(f"\n  SKIP Network: {net_csv} not found or empty. Run dataset_processor.py first.")

    # Splunk pipeline
    sp_csv = PROCESSED_DIR / "splunk_merged.csv"
    if sp_csv.exists() and sp_csv.stat().st_size > 100:
        try:
            results["splunk"] = prepare_pipeline("Splunk", sp_csv, "splunk")
        except Exception as e:
            log.error(f"Splunk preparation failed: {e}")
            print(f"\n  ERROR (Splunk): {e}")
    else:
        print(f"\n  SKIP Splunk: {sp_csv} not found or empty. Run dataset_processor.py first.")

    elapsed = time.time() - t_start
    print_section("ML PREPARATION COMPLETE")
    for pipe, meta in results.items():
        print(f"\n  {pipe.upper()}")
        print(f"    Train records: {meta.get('n_train',0):,}")
        print(f"    Test records:  {meta.get('n_test',0):,}")
        print(f"    Features:      {meta.get('n_processed_features',0)}")
        print(f"    Classes:       {meta.get('classes','?')}")
    print(f"\n  Total elapsed: {elapsed:.1f}s")

if __name__ == "__main__":
    main()
