CREATE DATABASE IF NOT EXISTS soc_chess CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE soc_chess;

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(80) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'ANALYST',
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS datasets (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  filename VARCHAR(255) NOT NULL,
  filepath VARCHAR(500) NULL,
  format VARCHAR(20) DEFAULT 'CSV',
  records_count BIGINT UNSIGNED NULL,
  features_count INT UNSIGNED NULL,
  target_column VARCHAR(128) NULL,
  missing_values BIGINT UNSIGNED NULL,
  status ENUM('ready','processing','failed') NOT NULL DEFAULT 'ready',
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dataset_features (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  dataset_id INT UNSIGNED NOT NULL,
  feature_name VARCHAR(100) NOT NULL,
  data_type VARCHAR(50) NOT NULL,
  missing_count INT DEFAULT 0,
  sample_values TEXT,
  is_target BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS training_runs (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  dataset_id INT UNSIGNED NULL,
  model_name VARCHAR(80) NOT NULL DEFAULT 'MLP_Neural_Network',
  algorithm VARCHAR(100) DEFAULT 'MLPClassifier (3-Hidden-Layers)',
  hyperparameters JSON NULL,
  started_at DATETIME NULL,
  completed_at DATETIME NULL,
  duration_seconds DECIMAL(10,2) DEFAULT 0.00,
  status ENUM('queued','training','trained','failed') NOT NULL DEFAULT 'queued',
  accuracy DECIMAL(8,6) NULL,
  precision_score DECIMAL(8,6) NULL,
  recall_score DECIMAL(8,6) NULL,
  f1_score DECIMAL(8,6) NULL,
  model_path VARCHAR(500) NULL,
  model_version VARCHAR(50) NULL,
  error_message TEXT NULL,
  CONSTRAINT fk_training_dataset FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS model_versions (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  version VARCHAR(50) UNIQUE NOT NULL,
  model_path VARCHAR(500) NOT NULL,
  preprocessor_path VARCHAR(500),
  training_run_id INT UNSIGNED NULL,
  features JSON,
  target_classes JSON,
  architecture JSON,
  status VARCHAR(50) DEFAULT 'READY',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_version (version)
);

CREATE TABLE IF NOT EXISTS model_metrics (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  training_run_id INT UNSIGNED NULL,
  model_version VARCHAR(50) NULL,
  metric_name VARCHAR(100) NOT NULL,
  metric_value JSON NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_metrics_run FOREIGN KEY (training_run_id) REFERENCES training_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_alerts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  occurred_at DATETIME NULL,
  source_ip VARCHAR(45) NULL,
  destination_ip VARCHAR(45) NULL,
  source_port INT NULL,
  destination_port INT NULL,
  protocol VARCHAR(20) NULL,
  attack_type VARCHAR(120) NOT NULL,
  confidence DECIMAL(6,5) NOT NULL,
  mlp_confidence DECIMAL(6,5) NULL,
  risk_score DECIMAL(5,2) NOT NULL,
  risk_status ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'LOW',
  severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'LOW',
  source VARCHAR(50) DEFAULT 'NETWORK',
  status VARCHAR(50) DEFAULT 'open',
  investigation_status ENUM('UNASSIGNED','INVESTIGATING','RESOLVED','ESCALATED') DEFAULT 'UNASSIGNED',
  evidence JSON NULL,
  threat_intel JSON NULL,
  llm_explanation TEXT NULL,
  recommended_action TEXT NULL,
  model_version VARCHAR(50) NULL,
  spark_job_id VARCHAR(100) NULL,
  raw_event JSON NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_severity (severity),
  INDEX idx_risk_status (risk_status),
  INDEX idx_source (source),
  INDEX idx_timestamp (timestamp)
);

CREATE TABLE IF NOT EXISTS spark_jobs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  job_id VARCHAR(100) UNIQUE NOT NULL,
  job_type VARCHAR(50) NOT NULL,
  dataset_name VARCHAR(255) NULL,
  status ENUM('QUEUED','RUNNING','COMPLETED','FAILED') NOT NULL DEFAULT 'QUEUED',
  records_processed BIGINT UNSIGNED DEFAULT 0,
  execution_time_ms INT DEFAULT 0,
  details JSON NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS splunk_queries (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  query_text TEXT NOT NULL,
  earliest_time VARCHAR(50) NULL,
  latest_time VARCHAR(50) NULL,
  executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  result_count INT UNSIGNED NULL,
  execution_time_ms INT DEFAULT 0,
  status VARCHAR(50) DEFAULT 'SUCCESS',
  error_message TEXT NULL
);

CREATE TABLE IF NOT EXISTS network_sessions (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  session_id VARCHAR(100) UNIQUE NOT NULL,
  interface VARCHAR(100) NOT NULL,
  start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  end_time TIMESTAMP NULL,
  packet_count INT DEFAULT 0,
  status VARCHAR(50) DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS network_events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  session_id VARCHAR(100),
  packet_no INT,
  source_ip VARCHAR(45),
  destination_ip VARCHAR(45),
  source_port INT,
  destination_port INT,
  protocol VARCHAR(20),
  packet_length INT,
  tcp_flags VARCHAR(50),
  interface VARCHAR(100),
  classification VARCHAR(50),
  confidence DECIMAL(5,2),
  risk_score DECIMAL(5,2) NULL,
  INDEX idx_proto (protocol),
  INDEX idx_src (source_ip),
  INDEX idx_dst (destination_ip),
  INDEX idx_timestamp (timestamp)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  action VARCHAR(100) NOT NULL,
  user VARCHAR(100) DEFAULT 'admin',
  ip_address VARCHAR(45) DEFAULT '127.0.0.1',
  details JSON NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ioc_analysis (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ioc VARCHAR(255) NOT NULL,
  ioc_type VARCHAR(50) NOT NULL,
  classification VARCHAR(50) DEFAULT 'UNKNOWN',
  threat_score DECIMAL(5,2) DEFAULT 0.00,
  reputation VARCHAR(50) DEFAULT 'UNKNOWN',
  confidence DECIMAL(5,2) DEFAULT 0.00,
  source VARCHAR(100) DEFAULT 'Local IOC Database',
  first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  observation_count INT DEFAULT 1,
  related_alerts_count INT DEFAULT 0,
  related_incidents_count INT DEFAULT 0,
  raw_threat_intel JSON,
  ai_analysis JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_ioc (ioc),
  INDEX idx_type (ioc_type),
  INDEX idx_class (classification)
);

CREATE TABLE IF NOT EXISTS incident_response (
  id INT AUTO_INCREMENT PRIMARY KEY,
  incident_id VARCHAR(100) UNIQUE NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  alert_id INT NULL,
  attack_type VARCHAR(100) NOT NULL,
  severity VARCHAR(20) DEFAULT 'MEDIUM',
  priority VARCHAR(20) DEFAULT 'P3',
  status VARCHAR(50) DEFAULT 'NEW',
  risk_score DECIMAL(5,2) DEFAULT 0.00,
  risk_status VARCHAR(20) DEFAULT 'LOW',
  mlp_confidence DECIMAL(6,3) DEFAULT 0.00,
  source_ip VARCHAR(45),
  destination_ip VARCHAR(45),
  source_port INT,
  destination_port INT,
  protocol VARCHAR(20),
  assigned_analyst VARCHAR(100) DEFAULT 'Senior SOC Analyst',
  threat_intel JSON,
  evidence JSON,
  splunk_evidence JSON,
  ai_investigation JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_inc_id (incident_id),
  INDEX idx_inc_status (status),
  INDEX idx_inc_sev (severity),
  INDEX idx_inc_atk (attack_type)
);

CREATE TABLE IF NOT EXISTS incident_timeline (
  id INT AUTO_INCREMENT PRIMARY KEY,
  incident_id VARCHAR(100) NOT NULL,
  action VARCHAR(100) NOT NULL,
  old_status VARCHAR(50),
  new_status VARCHAR(50),
  analyst VARCHAR(100) DEFAULT 'Senior SOC Analyst',
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_inc_timeline (incident_id)
);

CREATE TABLE IF NOT EXISTS soc_cases (
  id INT AUTO_INCREMENT PRIMARY KEY,
  case_id VARCHAR(100) UNIQUE NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  priority VARCHAR(20) DEFAULT 'MEDIUM',
  status VARCHAR(50) DEFAULT 'OPEN',
  assigned_analyst VARCHAR(100) DEFAULT 'Lead Threat Analyst',
  related_incident_id VARCHAR(100) NULL,
  related_alert_id INT NULL,
  related_ioc VARCHAR(255) NULL,
  ai_summary JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_case_id (case_id),
  INDEX idx_case_status (status),
  INDEX idx_case_priority (priority)
);

CREATE TABLE IF NOT EXISTS case_notes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  case_id VARCHAR(100) NOT NULL,
  analyst VARCHAR(100) DEFAULT 'Analyst',
  note_type VARCHAR(50) DEFAULT 'Investigation Note',
  note TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_case_notes (case_id)
);

CREATE TABLE IF NOT EXISTS case_evidence (
  id INT AUTO_INCREMENT PRIMARY KEY,
  case_id VARCHAR(100) NOT NULL,
  evidence_type VARCHAR(50) NOT NULL,
  reference_id VARCHAR(255),
  title VARCHAR(255),
  details JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_case_evidence (case_id)
);

CREATE TABLE IF NOT EXISTS llm_analysis_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  analysis_type VARCHAR(50) NOT NULL,
  reference_id VARCHAR(255),
  provider VARCHAR(50) NOT NULL,
  model VARCHAR(100),
  status VARCHAR(50) DEFAULT 'SUCCESS',
  input_payload JSON,
  output_response JSON,
  duration_ms INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_llm_ref (reference_id),
  INDEX idx_llm_type (analysis_type)
);

CREATE TABLE IF NOT EXISTS reports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  report_id VARCHAR(100) UNIQUE NOT NULL,
  report_type VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  reference_id VARCHAR(255),
  content JSON NOT NULL,
  summary TEXT,
  generated_by VARCHAR(100) DEFAULT 'NVIDIA AI SOC Analyst',
  format VARCHAR(20) DEFAULT 'JSON',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_report_id (report_id),
  INDEX idx_report_type (report_type)
);

CREATE TABLE IF NOT EXISTS system_connections (
  name VARCHAR(80) PRIMARY KEY,
  connected BOOLEAN NOT NULL,
  checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  details JSON NULL
);
