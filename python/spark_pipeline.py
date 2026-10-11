#!/usr/bin/env python3
"""
================================================================================
SOC CHESS -- Apache Spark Big Data Pipeline CLI
================================================================================
Runs Spark Big Data batch processing across network traffic and Splunk logs.
================================================================================
"""

import sys
import time
import json
from pathlib import Path

_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

from backend.config import settings
from backend.spark_engine.spark_manager import spark_manager
from backend.spark_engine.spark_processor import spark_processor

def main():
    print("=" * 70)
    print(" SOC CHESS -- APACHE SPARK BIG DATA INGESTION PIPELINE")
    print("=" * 70)
    status = spark_manager.get_status()
    print(f"[*] Engine Status: {status['status']}")
    print(f"[*] Spark Master : {status['master']}")
    print(f"[*] Memory Alloc : Driver={status['driver_memory']}, Executor={status['executor_memory']}")
    print(f"[*] Partitions   : {status['partitions']}")
    print(f"[*] Java Home    : {status['java_home']}")

    dataset_root = settings.DATASET_ROOT
    print(f"\n[*] Scanning dataset directory: {dataset_root}...")
    files = list(dataset_root.glob("**/*.csv")) + list(dataset_root.glob("**/*.log"))
    print(f"[*] Found {len(files)} dataset files.")

    total_records = 0
    start_t = time.time()
    for f in files[:3]:
        print(f"    - Spark processing {f.name}...")
        df = spark_manager.load_dataset_spark(f, max_rows=10000)
        total_records += len(df)
        print(f"      Ingested {len(df):,} records, {len(df.columns)} columns.")

    dur = round(time.time() - start_t, 2)
    print("\n" + "=" * 70)
    print(f"[*] Completed Spark Batch Ingestion: {total_records:,} total records in {dur}s ({round(total_records/max(0.01, dur), 1)} rec/s)")
    print("=" * 70)

if __name__ == "__main__":
    main()
