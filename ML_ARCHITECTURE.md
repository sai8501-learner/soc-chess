# SOC CHESS — Machine Learning & MLOps Architecture

This document provides a comprehensive operational blueprint of the Machine Learning, Big Data, and Real-Time Inference subsystems in the **SOC CHESS Platform**.

---

## 1. High-Level Architecture Overview

The system implements a **Dual-Tier Hybrid Architecture**:

```
+-----------------------------------------------------------------------------------+
|                            INGESTION & BIG DATA LAYER                             |
|  - 3,708 Dataset Files (CIC-IDS 2017/2018, UNSW-NB15, KDD-99, Splunk Attack Logs)|
|  - Apache Spark v3.5.3 (8 Partitions, 2 GB Driver, 2 GB Executor)                |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        CANONICAL FEATURE EXTRACTION                               |
|  - 19 Canonical Network Flow Features (Ports, Durations, Rates, TCP Flags)        |
|  - 19 Canonical Security Log Features (Event Codes, Admin Checks, Process Trees)   |
|  - Symmetrical Log1p Smoothing & Outlier Shielding                                |
+-----------------------------------------------------------------------------------+
                     |                                       |
                     v                                       v
+------------------------------------+   +------------------------------------------+
|      TIER 1: HIGH-CAPACITY BATCH   |   |        TIER 2: REAL-TIME STREAMING       |
|          CHAMPION ENSEMBLE         |   |          MLP NEURAL NETWORK              |
| - Random Forest (200 Trees)        |   | - 3-Hidden-Layer MLP (128 -> 64 -> 32)   |
| - XGBoost Multi-Class Classifier   |   | - Sub-millisecond serving latency        |
| - 99.39% Accuracy / 99.39% F1      |   | - 98.20% Accuracy / 99.20% ROC-AUC       |
+------------------------------------+   +------------------------------------------+
                     \                                       /
                      +-------------------------------------+
                      |       RISK SCORING & MITRE ATT&CK   |
                      | - Normalized Threat Score (0-100)   |
                      | - Adversarial Tactical Chess Mapping|
                      | - Real-time Tensor Norm Explainers  |
                      +-------------------------------------+
```

---

## 2. Directory Layout & Storage Standards

```
soc-chess/
├── datasets/                               # Unified Big Data Storage
│   ├── network/                            # 30 Raw Network Flow CSVs (8.09 GB)
│   ├── Splunk-Attack-Data/datasets/        # 3,655 Telemetry & Log Files (16 MB)
│   ├── processed/                          # Preprocessed Arrays & Merged CSVs
│   └── samples/                            # Validated Diagnostic PCAPs & EVTX
│
├── models/                                 # Primary Model Artifact Registry
│   ├── network/                            # Random Forest & XGBoost Artifacts
│   │   ├── random_forest.pkl               # Champion Model Weights
│   │   ├── xgboost.json                    # Secondary Ensemble Model
│   │   ├── preprocessor.pkl                # Fitted Feature Pipeline
│   │   ├── label_encoder.pkl               # Target Class Map
│   │   └── best_model.json                 # Active Champion Metadata
│   └── splunk/                             # Splunk Event Models
│       ├── random_forest.pkl               # Champion Log Model (91.86% Acc)
│       └── best_model.json                 # Operational Metadata
│
├── ml/models/                              # Real-Time Streaming Neural Net Registry
│   └── network/
│       ├── mlp_model.joblib                # 3-Hidden-Layer MLP Weights
│       ├── scaler.joblib                   # Fitted StandardScaler
│       ├── label_encoder.joblib            # 9-Class Canonical Encoder
│       └── metrics.json                    # Telemetry & ROC-AUC Scores
│
├── backend/ml_engine/                      # Core ML Python Engine
│   ├── dataset_detector.py                 # File & Modality Fingerprinter
│   ├── mlp_pipeline.py                     # Neural Network Pipeline
│   ├── log_pipeline.py                     # Windows/Splunk Extractor
│   ├── network_pipeline.py                 # Network Flow Extractor
│   └── risk_engine.py                      # Risk & Severity Calculator
│
├── ml_tool.py                              # Unified MLOps Management CLI
└── verify_datasets_and_model.py            # Automated Integrity Verification Suite
```

---

## 3. Canonical Feature Contracts

### 3.1 Network Features (19 Inputs)
`src_port`, `dst_port`, `protocol`, `flow_duration`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`, `flow_bytes_s`, `flow_packets_s`, `packet_length_mean`, `packet_length_std`, `syn_flag_cnt`, `ack_flag_cnt`, `psh_flag_cnt`, `fin_flag_cnt`, `rst_flag_cnt`, `init_fwd_win_byts`, `init_bwd_win_byts`.

### 3.2 Log Features (19 Inputs)
`event_code`, `is_system_account`, `is_admin_account`, `account_name_len`, `has_domain`, `has_powershell`, `has_cmd`, `is_suspicious_process`, `msg_length`, `msg_contains_ip`, `msg_contains_domain`, `msg_has_failed_auth`, `msg_has_success_auth`, `msg_has_privilege`, `msg_has_group_mod`, `msg_has_service`, `hour`, `day_of_week`, `source_ip_freq`.

---

## 4. MLOps Command Line Interface (`ml_tool.py`)

Run diagnostics and operations via the command line:

```bash
# 1. View model status, champions, accuracy, and infrastructure
python ml_tool.py status

# 2. Run real-time live inference tests on all registered models
python ml_tool.py test

# 3. View the 9-Pillar Maturity Scorecard and benchmarks
python ml_tool.py score

# 4. Audit dataset counts and sizes in the Big Data layer
python ml_tool.py inventory
```

---

## 5. Verified Performance Benchmarks

| Model Pipeline | Algorithm | Accuracy | Weighted F1 | ROC-AUC | Latency |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Network Batch** | Random Forest | **99.39%** | **99.39%** | **99.91%** | 0.42 ms |
| **Network Secondary** | XGBoost | **99.37%** | **99.37%** | **99.88%** | 0.48 ms |
| **Spark Streaming** | 3-Layer MLP Net | **98.20%** | **98.10%** | **99.20%** | 0.85 ms |
| **Security Logs** | Random Forest | **91.86%** | **91.03%** | **95.40%** | 1.10 ms |
