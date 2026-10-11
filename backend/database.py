import pymysql
import sqlite3
import json
import logging
from typing import List, Dict, Any, Optional
from backend.config import settings

logger = logging.getLogger("socchess.database")

_using_sqlite: bool = False

def is_using_sqlite() -> bool:
    global _using_sqlite
    return _using_sqlite

def _sqlite_get_connection():
    conn = sqlite3.connect(str(settings.SQLITE_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _sqlite_convert_params(params: Optional[tuple]) -> tuple:
    if not params:
        return ()
    converted = []
    for p in params:
        if isinstance(p, (dict, list)):
            converted.append(json.dumps(p))
        else:
            converted.append(p)
    return tuple(converted)

def _init_sqlite():
    global _using_sqlite
    _using_sqlite = True
    conn = sqlite3.connect(str(settings.SQLITE_DB_PATH), check_same_thread=False)
    try:
        cur = conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS datasets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                format TEXT NOT NULL,
                size_mb REAL DEFAULT 0.00,
                row_count INTEGER DEFAULT 0,
                column_count INTEGER DEFAULT 0,
                target_column TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS dataset_features (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_id INTEGER NOT NULL,
                feature_name TEXT NOT NULL,
                data_type TEXT NOT NULL,
                missing_count INTEGER DEFAULT 0,
                sample_values TEXT,
                is_target INTEGER DEFAULT 0,
                FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS training_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_id INTEGER,
                algorithm TEXT DEFAULT 'MLPClassifier (3-Hidden-Layers)',
                hyperparameters TEXT,
                status TEXT DEFAULT 'Queued',
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                duration_seconds REAL DEFAULT 0.00,
                error_message TEXT,
                model_version TEXT,
                accuracy REAL,
                precision_score REAL,
                recall_score REAL,
                f1_score REAL,
                model_path TEXT
            );
            CREATE TABLE IF NOT EXISTS model_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT UNIQUE NOT NULL,
                model_path TEXT NOT NULL,
                preprocessor_path TEXT,
                training_run_id INTEGER,
                features TEXT,
                target_classes TEXT,
                architecture TEXT,
                status TEXT DEFAULT 'READY',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS model_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_version TEXT NOT NULL,
                accuracy REAL,
                precision_score REAL,
                recall_score REAL,
                f1_score REAL,
                roc_auc REAL,
                confusion_matrix TEXT,
                classification_report TEXT,
                loss_curve TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ai_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                attack_type TEXT,
                confidence REAL,
                mlp_confidence REAL,
                risk_score REAL,
                risk_status TEXT DEFAULT 'LOW',
                severity TEXT DEFAULT 'LOW',
                source TEXT DEFAULT 'NETWORK',
                status TEXT DEFAULT 'NEW',
                investigation_status TEXT DEFAULT 'UNASSIGNED',
                recommended_action TEXT,
                evidence TEXT,
                threat_intel TEXT,
                llm_explanation TEXT,
                model_version TEXT,
                spark_job_id TEXT,
                raw_event TEXT
            );
            CREATE TABLE IF NOT EXISTS spark_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT UNIQUE NOT NULL,
                job_type TEXT NOT NULL,
                dataset_name TEXT,
                status TEXT DEFAULT 'QUEUED',
                records_processed INTEGER DEFAULT 0,
                execution_time_ms INTEGER DEFAULT 0,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS splunk_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_text TEXT NOT NULL,
                earliest_time TEXT,
                latest_time TEXT,
                result_count INTEGER DEFAULT 0,
                execution_time_ms INTEGER DEFAULT 0,
                status TEXT DEFAULT 'SUCCESS',
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS network_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                interface TEXT NOT NULL,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                packet_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'ACTIVE'
            );
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_id TEXT,
                packet_no INTEGER,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                packet_length INTEGER,
                tcp_flags TEXT,
                interface TEXT,
                classification TEXT,
                confidence REAL,
                risk_score REAL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                user TEXT DEFAULT 'admin',
                ip_address TEXT DEFAULT '127.0.0.1',
                details TEXT
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'ANALYST',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ioc_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                classification TEXT DEFAULT 'UNKNOWN',
                threat_score REAL DEFAULT 0.00,
                reputation TEXT DEFAULT 'UNKNOWN',
                confidence REAL DEFAULT 0.00,
                source TEXT DEFAULT 'Local IOC Database',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                observation_count INTEGER DEFAULT 1,
                related_alerts_count INTEGER DEFAULT 0,
                related_incidents_count INTEGER DEFAULT 0,
                raw_threat_intel TEXT,
                ai_analysis TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS incident_response (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                alert_id INTEGER,
                attack_type TEXT NOT NULL,
                severity TEXT DEFAULT 'MEDIUM',
                priority TEXT DEFAULT 'P3',
                status TEXT DEFAULT 'NEW',
                risk_score REAL DEFAULT 0.00,
                risk_status TEXT DEFAULT 'LOW',
                mlp_confidence REAL DEFAULT 0.00,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                assigned_analyst TEXT DEFAULT 'Senior SOC Analyst',
                threat_intel TEXT,
                evidence TEXT,
                splunk_evidence TEXT,
                ai_investigation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT,
                analyst TEXT DEFAULT 'Senior SOC Analyst',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS soc_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                priority TEXT DEFAULT 'MEDIUM',
                status TEXT DEFAULT 'OPEN',
                assigned_analyst TEXT DEFAULT 'Lead Threat Analyst',
                related_incident_id TEXT,
                related_alert_id INTEGER,
                related_ioc TEXT,
                ai_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                analyst TEXT DEFAULT 'Analyst',
                note_type TEXT DEFAULT 'Investigation Note',
                note TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS case_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                reference_id TEXT,
                title TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS llm_analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_type TEXT NOT NULL,
                reference_id TEXT,
                provider TEXT NOT NULL,
                model TEXT,
                status TEXT DEFAULT 'SUCCESS',
                input_payload TEXT,
                output_response TEXT,
                duration_ms INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE NOT NULL,
                report_type TEXT NOT NULL,
                title TEXT NOT NULL,
                reference_id TEXT,
                content TEXT NOT NULL,
                summary TEXT,
                generated_by TEXT DEFAULT 'NVIDIA AI SOC Analyst',
                format TEXT DEFAULT 'JSON',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        logger.info(f"[*] Autonomous SQLite database initialized successfully at {settings.SQLITE_DB_PATH}.")
    finally:
        conn.close()

def get_connection(use_database: bool = True):
    """Establishes a connection to MySQL."""
    kwargs = {
        "host": settings.MYSQL_HOST,
        "port": settings.MYSQL_PORT,
        "user": settings.MYSQL_USERNAME,
        "password": settings.MYSQL_PASSWORD,
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": True
    }
    if use_database:
        kwargs["database"] = settings.MYSQL_DATABASE
    return pymysql.connect(**kwargs)

def init_db():
    """Initializes database schema with MySQL or autonomous SQLite fallback."""
    global _using_sqlite
    if settings.USE_SQLITE:
        _init_sqlite()
        return
    try:
        # 1. Ensure database exists
        conn = get_connection(use_database=False)
        with conn.cursor() as cur:
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{settings.MYSQL_DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        conn.close()

        # 2. Create tables
        conn = get_connection(use_database=True)
        with conn.cursor() as cur:
            # Datasets Catalog
            cur.execute("""
                CREATE TABLE IF NOT EXISTS datasets (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    filepath VARCHAR(500) NOT NULL,
                    format VARCHAR(20) NOT NULL,
                    size_mb DECIMAL(10,2) DEFAULT 0.00,
                    row_count INT DEFAULT 0,
                    column_count INT DEFAULT 0,
                    target_column VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_format (format)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Dataset Features Schema
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dataset_features (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    dataset_id INT NOT NULL,
                    feature_name VARCHAR(100) NOT NULL,
                    data_type VARCHAR(50) NOT NULL,
                    missing_count INT DEFAULT 0,
                    sample_values TEXT,
                    is_target BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE,
                    INDEX idx_dataset (dataset_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Training Runs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS training_runs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    dataset_id INT,
                    algorithm VARCHAR(100) DEFAULT 'MLPClassifier (3-Hidden-Layers)',
                    hyperparameters JSON,
                    status VARCHAR(50) DEFAULT 'Queued',
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP NULL,
                    duration_seconds DECIMAL(10,2) DEFAULT 0.00,
                    error_message TEXT,
                    model_version VARCHAR(50),
                    accuracy DECIMAL(8,6) NULL,
                    precision_score DECIMAL(8,6) NULL,
                    recall_score DECIMAL(8,6) NULL,
                    f1_score DECIMAL(8,6) NULL,
                    model_path VARCHAR(500) NULL,
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Model Versions
            cur.execute("""
                CREATE TABLE IF NOT EXISTS model_versions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    version VARCHAR(50) UNIQUE NOT NULL,
                    model_path VARCHAR(500) NOT NULL,
                    preprocessor_path VARCHAR(500),
                    training_run_id INT,
                    features JSON,
                    target_classes JSON,
                    architecture JSON,
                    status VARCHAR(50) DEFAULT 'READY',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_version (version)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Model Metrics
            cur.execute("""
                CREATE TABLE IF NOT EXISTS model_metrics (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    model_version VARCHAR(50) NOT NULL,
                    accuracy DECIMAL(6,4),
                    precision_score DECIMAL(6,4),
                    recall_score DECIMAL(6,4),
                    f1_score DECIMAL(6,4),
                    roc_auc DECIMAL(6,4),
                    confusion_matrix JSON,
                    classification_report JSON,
                    loss_curve JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_model_version (model_version)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # AI Alerts (Enhanced for Spark + MLP + Risk Engine + Threat Intel + LLM)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ai_alerts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip VARCHAR(45),
                    destination_ip VARCHAR(45),
                    source_port INT,
                    destination_port INT,
                    protocol VARCHAR(20),
                    attack_type VARCHAR(100),
                    confidence DECIMAL(6,3),
                    mlp_confidence DECIMAL(6,3),
                    risk_score DECIMAL(5,2),
                    risk_status VARCHAR(20) DEFAULT 'LOW',
                    severity VARCHAR(20) DEFAULT 'LOW',
                    source VARCHAR(50) DEFAULT 'NETWORK',
                    status VARCHAR(50) DEFAULT 'NEW',
                    investigation_status VARCHAR(50) DEFAULT 'UNASSIGNED',
                    recommended_action TEXT,
                    evidence JSON,
                    threat_intel JSON,
                    llm_explanation TEXT,
                    model_version VARCHAR(50),
                    spark_job_id VARCHAR(100),
                    raw_event JSON,
                    INDEX idx_severity (severity),
                    INDEX idx_risk_status (risk_status),
                    INDEX idx_source (source),
                    INDEX idx_timestamp (timestamp)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Migration: Ensure ai_alerts has all new columns
            for col_sql in [
                "ALTER TABLE ai_alerts ADD COLUMN mlp_confidence DECIMAL(6,3) NULL AFTER confidence;",
                "ALTER TABLE ai_alerts ADD COLUMN risk_status VARCHAR(20) DEFAULT 'LOW' AFTER risk_score;",
                "ALTER TABLE ai_alerts ADD COLUMN investigation_status VARCHAR(50) DEFAULT 'UNASSIGNED' AFTER status;",
                "ALTER TABLE ai_alerts ADD COLUMN evidence JSON NULL AFTER recommended_action;",
                "ALTER TABLE ai_alerts ADD COLUMN threat_intel JSON NULL AFTER evidence;",
                "ALTER TABLE ai_alerts ADD COLUMN llm_explanation TEXT NULL AFTER threat_intel;",
                "ALTER TABLE ai_alerts ADD COLUMN spark_job_id VARCHAR(100) NULL AFTER model_version;",
            ]:
                try:
                    cur.execute(col_sql)
                except Exception:
                    pass

            # Spark Jobs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS spark_jobs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    job_id VARCHAR(100) UNIQUE NOT NULL,
                    job_type VARCHAR(50) NOT NULL,
                    dataset_name VARCHAR(255),
                    status VARCHAR(50) DEFAULT 'QUEUED',
                    records_processed BIGINT DEFAULT 0,
                    execution_time_ms INT DEFAULT 0,
                    details JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_spark_job (job_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Splunk Queries & Logs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS splunk_queries (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    query_text TEXT NOT NULL,
                    earliest_time VARCHAR(50),
                    latest_time VARCHAR(50),
                    result_count INT DEFAULT 0,
                    execution_time_ms INT DEFAULT 0,
                    status VARCHAR(50) DEFAULT 'SUCCESS',
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Network Sessions & Events
            cur.execute("""
                CREATE TABLE IF NOT EXISTS network_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_id VARCHAR(100) UNIQUE NOT NULL,
                    interface VARCHAR(100) NOT NULL,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP NULL,
                    packet_count INT DEFAULT 0,
                    status VARCHAR(50) DEFAULT 'ACTIVE'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS network_events (
                    id INT AUTO_INCREMENT PRIMARY KEY,
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Audit Logs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    action VARCHAR(100) NOT NULL,
                    user VARCHAR(100) DEFAULT 'admin',
                    ip_address VARCHAR(45) DEFAULT '127.0.0.1',
                    details TEXT
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Users
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'ANALYST',
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # 1. IOC Intelligence & Analysis Table
            cur.execute("""
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # 2. Incident Response Table (9-Stage Workflow)
            cur.execute("""
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # 3. Incident Timeline Audit Log
            cur.execute("""
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # 4. SOC Cases Management Table
            cur.execute("""
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # 5. SOC Case Notes
            cur.execute("""
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    case_id VARCHAR(100) NOT NULL,
                    analyst VARCHAR(100) DEFAULT 'Analyst',
                    note_type VARCHAR(50) DEFAULT 'Investigation Note',
                    note TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_case_notes (case_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # 6. SOC Case Evidence Attachments
            cur.execute("""
                CREATE TABLE IF NOT EXISTS case_evidence (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    case_id VARCHAR(100) NOT NULL,
                    evidence_type VARCHAR(50) NOT NULL,
                    reference_id VARCHAR(255),
                    title VARCHAR(255),
                    details JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_case_evidence (case_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # 7. LLM Analysis & Audit History
            cur.execute("""
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # 8. SOC Reports Table
            cur.execute("""
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            cur.execute(
                "DELETE FROM users WHERE username = %s AND email = %s AND password_hash = %s",
                (
                    "admin",
                    "admin@soc-chess.local",
                    "$2y$10$6FuSZ2fB53pHb1KvdmJIjeb45aBMkI.3KsOGZvD6tWA4W0RqcYK0W",
                ),
            )

        conn.close()
        _using_sqlite = False
        logger.info("[*] MySQL database and tables initialized successfully.")
    except Exception as e:
        logger.warning(f"[!] MySQL initialization failed ({e}). Activating autonomous embedded SQLite fallback for cloud deployment.")
        _init_sqlite()

def query(sql: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
    """Executes a SELECT query and returns rows."""
    if _using_sqlite:
        conn = _sqlite_get_connection()
        try:
            cur = conn.cursor()
            cur.execute(sql.replace("%s", "?"), _sqlite_convert_params(params))
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()
    finally:
        conn.close()

def query_one(sql: str, params: Optional[tuple] = None) -> Optional[Dict[str, Any]]:
    """Executes a SELECT query and returns a single row."""
    if _using_sqlite:
        conn = _sqlite_get_connection()
        try:
            cur = conn.cursor()
            cur.execute(sql.replace("%s", "?"), _sqlite_convert_params(params))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchone()
    finally:
        conn.close()

def execute(sql: str, params: Optional[tuple] = None) -> int:
    """Executes an INSERT/UPDATE/DELETE query and returns affected rows or last insert id."""
    if _using_sqlite:
        conn = _sqlite_get_connection()
        try:
            cur = conn.cursor()
            cur.execute(sql.replace("%s", "?"), _sqlite_convert_params(params))
            conn.commit()
            return cur.lastrowid or cur.rowcount
        finally:
            conn.close()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.lastrowid or cur.rowcount
    finally:
        conn.close()
