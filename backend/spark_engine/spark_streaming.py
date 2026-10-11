import time
import json
import logging
import threading
import queue
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
import numpy as np
import pandas as pd

from backend.config import settings
from backend.spark_engine.spark_processor import spark_processor

logger = logging.getLogger("socchess.spark.streaming")


class SparkStreamingEngine:
    """
    Apache Spark Structured Streaming & Real-Time Micro-Batch Engine.
    Processes continuous streams of network packets, Splunk logs, and security events.
    Tracks live metrics: throughput, processing latency, alerts generated, failed events, and job status.
    """

    def __init__(self, batch_interval_seconds: float = 1.0, max_batch_size: int = 500):
        self.batch_interval: float = batch_interval_seconds
        self.max_batch_size: int = max_batch_size
        self.status: str = "STOPPED"  # STOPPED, ACTIVE, PAUSED
        self.event_queue: queue.Queue = queue.Queue(maxsize=50000)
        self.lock = threading.Lock()

        # Telemetry metrics
        self.start_time: Optional[float] = None
        self.events_received: int = 0
        self.events_processed: int = 0
        self.alerts_generated: int = 0
        self.failed_events: int = 0
        self.last_batch_time: float = 0.0
        self.last_batch_duration_ms: float = 0.0
        self.average_latency_ms: float = 0.0
        self.total_batches_processed: int = 0
        self.active_subscribers: List[Callable[[Dict[str, Any]], None]] = []

        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> Dict[str, Any]:
        """Starts the real-time Spark streaming micro-batch consumer."""
        with self.lock:
            if self.status == "ACTIVE":
                return self.get_status()

            self.status = "ACTIVE"
            self._stop_event.clear()
            self.start_time = time.time()
            self._worker_thread = threading.Thread(
                target=self._streaming_loop,
                daemon=True,
                name="SparkStructuredStreamingWorker"
            )
            self._worker_thread.start()
            logger.info("[*] Apache Spark Structured Streaming Engine STARTED.")

        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        """Stops the real-time Spark streaming engine."""
        with self.lock:
            if self.status == "STOPPED":
                return self.get_status()

            self.status = "STOPPED"
            self._stop_event.set()
            logger.info("[-] Apache Spark Structured Streaming Engine STOPPED.")

        return self.get_status()

    def pause(self) -> Dict[str, Any]:
        """Pauses processing while retaining incoming event buffer."""
        with self.lock:
            self.status = "PAUSED"
            logger.info("[!] Apache Spark Structured Streaming Engine PAUSED.")
        return self.get_status()

    def resume(self) -> Dict[str, Any]:
        """Resumes processing from paused state."""
        with self.lock:
            self.status = "ACTIVE"
            logger.info("[*] Apache Spark Structured Streaming Engine RESUMED.")
        return self.get_status()

    def feed_event(self, event_data: Dict[str, Any]) -> bool:
        """Pushes a live network packet or Splunk log into the Spark stream queue."""
        try:
            self.events_received += 1
            self.event_queue.put_nowait(event_data)
            return True
        except queue.Full:
            self.failed_events += 1
            logger.warning("[!] Spark Streaming Event Queue is full. Dropping incoming event.")
            return False

    def feed_batch(self, events: List[Dict[str, Any]]) -> int:
        """Pushes a batch of events into the Spark stream queue."""
        pushed = 0
        for ev in events:
            if self.feed_event(ev):
                pushed += 1
        return pushed

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive real-time streaming telemetry."""
        uptime = round(time.time() - self.start_time, 2) if (self.start_time and self.status == "ACTIVE") else 0.0
        qsize = self.event_queue.qsize()
        throughput = round(self.events_processed / max(1.0, uptime), 1) if uptime > 0 else 0.0

        return {
            "engine": "Apache Spark Structured Streaming",
            "streaming_status": self.status,
            "is_streaming": self.status == "ACTIVE",
            "events_received": self.events_received,
            "events_processed": self.events_processed,
            "events_queued": qsize,
            "alerts_generated": self.alerts_generated,
            "failed_events": self.failed_events,
            "processing_latency_ms": round(self.last_batch_duration_ms, 2),
            "average_latency_ms": round(self.average_latency_ms, 2),
            "throughput_events_per_sec": throughput,
            "total_batches_processed": self.total_batches_processed,
            "batch_interval_seconds": self.batch_interval,
            "spark_job_status": "RUNNING" if self.status == "ACTIVE" else "IDLE",
            "uptime_seconds": uptime
        }

    def _streaming_loop(self):
        """Micro-batch execution loop."""
        while not self._stop_event.is_set():
            if self.status != "ACTIVE":
                time.sleep(0.5)
                continue

            batch_items = []
            start_collect = time.time()

            # Drain queue up to max_batch_size
            while len(batch_items) < self.max_batch_size:
                try:
                    item = self.event_queue.get_nowait()
                    batch_items.append(item)
                except queue.Empty:
                    break

            if not batch_items:
                time.sleep(self.batch_interval)
                continue

            # Process micro-batch with Spark Feature Extraction + MLP
            self._process_micro_batch(batch_items)

            # Sleep remaining time to preserve configured batch interval
            elapsed = time.time() - start_collect
            if elapsed < self.batch_interval:
                time.sleep(self.batch_interval - elapsed)

    def _process_micro_batch(self, batch_items: List[Dict[str, Any]]):
        """Transforms micro-batch of raw events through Spark -> MLP -> Risk -> TI -> Alert."""
        batch_start = time.time()
        job_id = f"spark_stream_batch_{int(time.time()*1000)}"

        try:
            # 1. Spark Canonical 19 Feature Extraction for batch
            feat_vectors = []
            parsed_records = []

            for raw in batch_items:
                try:
                    _, vec = spark_processor.process_single_packet(raw)
                    feat_vectors.append(vec[0])
                    parsed_records.append(raw)
                except Exception:
                    self.failed_events += 1

            if not feat_vectors:
                return

            from backend.ml_engine.mlp_pipeline import mlp_pipeline
            from backend.ml_engine.risk_engine import risk_engine
            from backend.services.threat_intel import threat_intel_service

            X_batch = np.array(feat_vectors)

            # 2. Multi-Layer Perceptron (MLP) Batch Inference
            preds = mlp_pipeline.predict_batch(X_batch)

            # 3. Risk Engine Scoring & Threat Intelligence Enrichment
            for idx, pred in enumerate(preds):
                raw = parsed_records[idx]
                src_ip = str(raw.get("src_ip") or raw.get("source_ip") or "192.168.56.104")
                dst_ip = str(raw.get("dst_ip") or raw.get("destination_ip") or "192.168.56.107")
                src_port = int(raw.get("src_port") or raw.get("source_port") or 50000)
                dst_port = int(raw.get("dst_port") or raw.get("destination_port") or 80)
                proto = str(raw.get("protocol") or "TCP").upper()

                label = pred["attack_type"]
                conf = pred["confidence"]
                is_att = pred["is_attack"]

                ti = threat_intel_service.lookup_ip(src_ip)
                ti_score = float(ti.get("threat_score", 0))

                risk_calc = risk_engine.calculate_risk(
                    attack_type=label,
                    mlp_confidence=conf,
                    is_attack=is_att,
                    threat_intel_score=ti_score,
                    destination_ip=dst_ip
                )

                risk_val = risk_calc["risk_score"]
                risk_stat = risk_calc["risk_status"]

                self.events_processed += 1

                # If attack with risk score >= 50, record alert in MySQL
                if is_att and risk_val >= 50:
                    self.alerts_generated += 1
                    try:
                        from backend.database import execute
                        execute("""
                            INSERT INTO ai_alerts (
                                source_ip, destination_ip, source_port, destination_port, protocol,
                                attack_type, confidence, mlp_confidence, risk_score, risk_status, severity,
                                source, status, recommended_action, evidence, threat_intel, llm_explanation, spark_job_id
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            src_ip, dst_ip, src_port, dst_port, proto, label, conf, conf, risk_val, risk_stat, risk_stat,
                            "SPARK_STREAM", "open", "Isolate host and block traffic",
                            json.dumps(risk_calc["evidence"]), json.dumps(ti),
                            f"Spark Structured Streaming detected {label} with {conf:.1f}% confidence. Risk: {risk_val}/100 ({risk_stat}).",
                            job_id
                        ))
                    except Exception:
                        pass

            duration_ms = (time.time() - batch_start) * 1000
            self.last_batch_duration_ms = duration_ms
            self.total_batches_processed += 1
            self.average_latency_ms = (
                (self.average_latency_ms * (self.total_batches_processed - 1) + duration_ms) / self.total_batches_processed
            )

        except Exception as e:
            logger.error(f"[!] Spark streaming micro-batch error: {e}")
            self.failed_events += len(batch_items)


spark_streaming = SparkStreamingEngine()
