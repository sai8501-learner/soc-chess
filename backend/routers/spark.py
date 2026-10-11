import time
from typing import Dict, Any, Optional, List
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.config import settings
from backend.spark_engine.spark_manager import spark_manager
from backend.spark_engine.spark_processor import spark_processor
from backend.spark_engine.spark_streaming import spark_streaming
from backend.database import query

router = APIRouter(prefix="/api/spark", tags=["Apache Spark Big Data & Streaming Engine"])


class ProcessDatasetRequest(BaseModel):
    dataset_path: str
    max_records: Optional[int] = 50000


class FeedStreamRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/status")
def get_spark_status():
    """Returns the live status, memory allocation, and batch metrics of Apache Spark."""
    batch_status = spark_manager.get_status()
    stream_status = spark_streaming.get_status()
    return {
        **batch_status,
        "streaming": stream_status
    }


@router.get("/stream/status")
def get_spark_stream_status():
    """Returns real-time Spark Structured Streaming metrics: status, latency, throughput, and queue depth."""
    return spark_streaming.get_status()


@router.post("/stream/start")
def start_spark_stream():
    """Starts the real-time Spark Structured Streaming micro-batch processing engine."""
    return spark_streaming.start()


@router.post("/stream/stop")
def stop_spark_stream():
    """Stops the real-time Spark Structured Streaming engine."""
    return spark_streaming.stop()


@router.post("/stream/feed")
def feed_spark_stream(req: FeedStreamRequest):
    """Pushes a live batch of network or log events into the Spark Structured Streaming engine."""
    if not req.events:
        raise HTTPException(status_code=400, detail="No events provided to feed into stream.")
    pushed = spark_streaming.feed_batch(req.events)
    return {
        "status": "QUEUED",
        "events_pushed": pushed,
        "queue_size": spark_streaming.event_queue.qsize()
    }


@router.get("/jobs")
def list_spark_jobs(limit: int = 50):
    """Lists recent Spark Big Data batch and streaming jobs recorded in MySQL."""
    try:
        rows = query("SELECT * FROM spark_jobs ORDER BY id DESC LIMIT %s", (min(limit, 100),))
        return {"jobs": rows}
    except Exception as e:
        return {"jobs": []}


@router.post("/process-dataset")
def process_dataset_with_spark(req: ProcessDatasetRequest):
    """Processes a large cybersecurity dataset through Apache Spark Data Cleaning & Feature Engineering."""
    file_path = (settings.DATASET_ROOT / req.dataset_path).resolve()
    if not file_path.exists():
        file_path = (settings.BASE_DIR / req.dataset_path).resolve()
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Dataset file not found: {req.dataset_path}")

    start_t = time.time()
    df = spark_manager.load_dataset_spark(file_path, max_rows=req.max_records)
    if df is None or len(df) == 0:
        raise HTTPException(status_code=400, detail="Failed to ingest dataset into Spark DataFrame.")

    cols = [str(c).strip().lower() for c in df.columns]
    is_log = any("event" in c or "account" in c or "message" in c for c in cols)

    if is_log:
        processed, feature_matrix, feature_names, _ = spark_processor.process_splunk_logs_dataframe(df)
        pipeline_type = "Spark Splunk Security Log Feature Extractor"
    else:
        processed, feature_matrix, feature_names = spark_processor.process_network_dataframe(df)
        pipeline_type = "Spark Network Flow Big Data Extractor"

    duration = round(time.time() - start_t, 2)
    return {
        "status": "SUCCESS",
        "pipeline": pipeline_type,
        "dataset": file_path.name,
        "records_ingested": len(df),
        "features_extracted": len(feature_names),
        "feature_names": feature_names,
        "duration_seconds": duration,
        "throughput_records_per_sec": round(len(df) / max(0.01, duration), 1),
        "spark_partitions": settings.SPARK_PARTITIONS
    }
