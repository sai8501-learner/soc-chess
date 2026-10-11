"""
================================================================================
SOC CHESS — Apache Spark Big Data & Streaming Engine
================================================================================
Provides enterprise Big Data data processing, ingestion, structured streaming,
and canonical feature engineering for cybersecurity datasets, network packets,
and Splunk SIEM security logs.
================================================================================
"""
from backend.spark_engine.spark_manager import spark_manager
from backend.spark_engine.spark_processor import spark_processor
from backend.spark_engine.spark_streaming import spark_streaming

__all__ = ["spark_manager", "spark_processor", "spark_streaming"]
