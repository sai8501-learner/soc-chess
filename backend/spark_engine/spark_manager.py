import os
import sys
import time
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from backend.config import settings

logger = logging.getLogger("socchess.spark.manager")

# Global PySpark handle
_spark_session = None
_spark_available = False
_spark_init_error = None


class SparkBigDataEngine:
    """
    Apache Spark Big Data Engine Manager for SOC Chess.
    Manages SparkSession, Java environment detection, cluster configuration,
    and distributed/partitioned Big Data data pipelines for network packets and Splunk logs.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.total_records_processed: int = 0
        self.total_jobs_executed: int = 0
        self.active_jobs: Dict[str, Dict[str, Any]] = {}
        self.start_time = time.time()
        self.session = None
        self.is_initialized = False
        self.init_attempted = False

    def _init_spark(self):
        """Attempts to initialize PySpark SparkSession with automatic Java detection."""
        global _spark_session, _spark_available, _spark_init_error

        if self.init_attempted:
            return

        self.init_attempted = True

        # Ensure JAVA_HOME is configured
        if settings.JAVA_HOME and not os.environ.get("JAVA_HOME"):
            os.environ["JAVA_HOME"] = settings.JAVA_HOME
            java_bin = str(Path(settings.JAVA_HOME) / "bin")
            if java_bin not in os.environ.get("PATH", ""):
                os.environ["PATH"] = f"{java_bin};{os.environ.get('PATH', '')}"
        os.environ.setdefault("PYSPARK_PYTHON", settings.PYSPARK_PYTHON)
        os.environ.setdefault("PYSPARK_DRIVER_PYTHON", settings.PYSPARK_DRIVER_PYTHON)

        if not settings.JAVA_HOME:
            _spark_init_error = "JAVA_HOME is not configured. Install a full JDK and set JAVA_HOME before enabling Spark."
            _spark_available = False
            self.is_initialized = False
            logger.warning("[!] %s", _spark_init_error)
            return

        try:
            import pyspark
            from pyspark.sql import SparkSession

            # Build optimized local SparkSession
            builder = (
                SparkSession.builder.appName(settings.SPARK_APP_NAME)
                .master(settings.SPARK_MASTER)
                .config("spark.driver.memory", settings.SPARK_DRIVER_MEMORY)
                .config("spark.executor.memory", settings.SPARK_EXECUTOR_MEMORY)
                .config("spark.sql.shuffle.partitions", str(settings.SPARK_PARTITIONS))
                .config("spark.sql.execution.arrow.pyspark.enabled", "true")
                .config("spark.driver.extraJavaOptions", "-Dfile.encoding=UTF-8")
                .config("spark.executor.extraJavaOptions", "-Dfile.encoding=UTF-8")
            )
            self.session = builder.getOrCreate()
            _spark_session = self.session
            _spark_available = True
            self.is_initialized = True
            logger.info(f"[*] Apache Spark {pyspark.__version__} Session successfully initialized.")
        except Exception as e:
            _spark_init_error = str(e)
            _spark_available = False
            self.session = None
            self.is_initialized = False
            logger.warning(f"[!] PySpark initialization note: {e}. Active partition engine enabled.")

    def ensure_initialized(self):
        """Initialize Spark only when a real Spark-based workload is requested."""
        if self.is_initialized or _spark_available:
            return
        self._init_spark()

    def get_status(self) -> Dict[str, Any]:
        """Returns live Apache Spark Big Data Engine status, memory allocation, and processing metrics."""
        uptime = round(time.time() - self.start_time, 2)
        pyspark_version = "3.5.3"
        try:
            import pyspark
            pyspark_version = pyspark.__version__
        except Exception:
            pass

        java_ok = bool(settings.JAVA_HOME and Path(settings.JAVA_HOME).exists())

        return {
            "engine": "Apache Spark Big Data Processing Layer",
            "version": pyspark_version,
            "status": "ONLINE" if _spark_available else ("DEGRADED" if _spark_init_error else "INITIALIZING"),
            "master": settings.SPARK_MASTER,
            "app_name": settings.SPARK_APP_NAME,
            "driver_memory": settings.SPARK_DRIVER_MEMORY,
            "executor_memory": settings.SPARK_EXECUTOR_MEMORY,
            "partitions": settings.SPARK_PARTITIONS,
            "java_home": settings.JAVA_HOME or "System Java Path",
            "java_available": java_ok,
            "pyspark_active": _spark_available,
            "initialization_error": _spark_init_error,
            "total_records_processed": self.total_records_processed,
            "total_jobs_executed": self.total_jobs_executed,
            "active_jobs_count": len(self.active_jobs),
            "uptime_seconds": uptime,
            "pipeline_stages": [
                "1. Data Ingestion (Network / Splunk / Datasets)",
                "2. Spark Partitioned Cleaning & Imputation",
                "3. Big Data Feature Extraction",
                "4. Vector Scaling & Normalization",
                "5. MLP Neural Network Classification",
                "6. Risk Score Engine (0-100)",
                "7. Threat Intelligence Enrichment",
                "8. LLM Security Analysis"
            ]
        }

    def record_job(self, job_id: str, job_type: str, records: int, duration_ms: int, details: Optional[Dict[str, Any]] = None):
        """Records completed Spark Big Data processing job metrics."""
        with self.lock:
            self.total_records_processed += records
            self.total_jobs_executed += 1
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]

        try:
            from backend.database import execute
            execute(
                "INSERT INTO spark_jobs (job_id, job_type, status, records_processed, execution_time_ms, details) "
                "VALUES (%s, %s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE status=%s, records_processed=%s, execution_time_ms=%s, details=%s;",
                (
                    job_id, job_type, "COMPLETED", records, duration_ms, json.dumps(details or {}),
                    "COMPLETED", records, duration_ms, json.dumps(details or {})
                )
            )
        except Exception as e:
            logger.warning(f"[!] Warning saving spark job to database: {e}")

    def load_dataset_spark(self, file_path: Path, max_rows: Optional[int] = None) -> pd.DataFrame:
        """
        Loads large datasets using Apache Spark DataFrame or chunked partitioned streams.
        Handles missing values, corrupted headers, and multi-gigabyte files.
        """
        start_t = time.time()
        job_id = f"spark_read_{int(time.time()*1000)}"
        self.active_jobs[job_id] = {"type": "DATASET_INGESTION", "file": file_path.name, "start": start_t}

        df = None
        ext = file_path.suffix.lower()

        # Handle JSON / JSONL files
        if ext in [".json", ".jsonl", ".ndjson"]:
            try:
                try:
                    df = pd.read_json(file_path, lines=(ext in [".jsonl", ".ndjson"]))
                except Exception:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                        raw_data = json.load(fp)
                    if isinstance(raw_data, list):
                        df = pd.DataFrame(raw_data)
                    elif isinstance(raw_data, dict):
                        for k, v in raw_data.items():
                            if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                                df = pd.DataFrame(v)
                                break
                        if df is None or len(df) == 0:
                            df = pd.DataFrame([raw_data])
                if max_rows and df is not None and len(df) > max_rows:
                    df = df.iloc[:max_rows]
            except Exception as e:
                logger.warning(f"[!] JSON ingestion error: {e}")

        # Handle LOG / TXT files
        elif ext in [".log", ".txt"]:
            try:
                df = pd.read_csv(file_path, sep=None, engine="python", on_bad_lines="skip", nrows=max_rows)
            except Exception:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                        lines = [l.strip() for l in fp if l.strip()]
                    if max_rows:
                        lines = lines[:max_rows]
                    df = pd.DataFrame([{"_raw": l, "message": l, "event_code": 4624} for l in lines])
                except Exception:
                    pass

        # 1. Try PySpark DataFrame Reader if active
        if df is None:
            self.ensure_initialized()
        if df is None and _spark_available and self.session is not None:
            try:
                sdf = self.session.read.option("header", "true").option("inferSchema", "true").csv(str(file_path))
                if max_rows:
                    sdf = sdf.limit(max_rows)
                df = sdf.toPandas()
                logger.info(f"[*] Spark successfully read {len(df)} records from {file_path.name}")
            except Exception as e:
                logger.warning(f"[!] Spark direct read fallback: {e}")

        # 2. High-performance chunked partitioned fallback for CSV/TSV/other tabular
        if df is None:
            chunks = []
            chunk_size = 50000
            total_read = 0
            for enc in ["utf-8", "latin-1", "cp1252"]:
                try:
                    for chunk in pd.read_csv(file_path, chunksize=chunk_size, encoding=enc, on_bad_lines="skip", low_memory=False):
                        chunks.append(chunk)
                        total_read += len(chunk)
                        if max_rows and total_read >= max_rows:
                            break
                    if chunks:
                        df = pd.concat(chunks, ignore_index=True)
                        if max_rows:
                            df = df.iloc[:max_rows]
                        break
                except Exception:
                    continue

        if df is None:
            df = pd.DataFrame()

        dur_ms = int((time.time() - start_t) * 1000)
        self.record_job(job_id, "DATASET_INGESTION", len(df), dur_ms, {"file": file_path.name, "columns": len(df.columns)})
        return df


spark_manager = SparkBigDataEngine()
