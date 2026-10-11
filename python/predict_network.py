#!/usr/bin/env python3
"""
================================================================================
SOC CHESS -- MLP NEURAL NETWORK PREDICTION ENGINE
================================================================================
Evaluates live network flows using:
  1. Apache Spark Feature Extractor
  2. 3-Hidden-Layer MLP Neural Network (128 -> 64 -> 32 ReLU)
  3. 0-100 Risk Score Engine (Low / Medium / High / Critical)
  4. Threat Intelligence IP Reputation Enrichment
  5. LLM SOC Analyst Security Explanation
================================================================================
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional

_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

from backend.spark_engine.spark_processor import spark_processor
from backend.ml_engine.mlp_pipeline import mlp_pipeline
from backend.ml_engine.risk_engine import risk_engine
from backend.services.threat_intel import threat_intel_service
from backend.services.llm_analyst import llm_analyst


class NetworkPredictor:
    """Production MLP Neural Network Predictor for SOC Chess."""

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = model_dir
        if not mlp_pipeline.is_loaded:
            mlp_pipeline._load_latest_model()

    def predict_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scores a single network flow through the complete Spark -> MLP -> Risk -> TI -> LLM pipeline.
        """
        src_ip = str(flow.get("src_ip") or flow.get("source_ip") or "192.168.56.104")
        dst_ip = str(flow.get("dst_ip") or flow.get("destination_ip") or "192.168.56.107")
        src_port = int(flow.get("src_port") or flow.get("source_port") or 50000)
        dst_port = int(flow.get("dst_port") or flow.get("destination_port") or 80)
        proto = str(flow.get("protocol") or "TCP").upper()

        # 1. Spark Feature Extraction
        _, feat_vector = spark_processor.process_single_packet(flow)

        # 2. MLP Neural Network Inference
        pred = mlp_pipeline.predict(feat_vector)
        attack_type = pred["attack_type"]
        confidence = pred["confidence"]
        is_attack = pred["is_attack"]

        # 3. Threat Intelligence Enrichment
        ti = threat_intel_service.lookup_ip(src_ip)
        ti_score = float(ti.get("threat_score", 0))

        # 4. Risk Score Engine
        risk_res = risk_engine.calculate_risk(
            attack_type=attack_type,
            mlp_confidence=confidence,
            is_attack=is_attack,
            threat_intel_score=ti_score,
            destination_ip=dst_ip
        )
        risk = risk_res["risk_score"]
        sev = risk_res["risk_status"]

        # 5. LLM SOC Analyst Assistant Report
        llm_report = llm_analyst.generate_investigation_report({
            "attack_type": attack_type,
            "mlp_confidence": confidence,
            "risk_score": risk,
            "risk_status": sev,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": proto,
            "threat_intel": ti
        })

        return {
            "prediction": attack_type,
            "attack_category": attack_type if is_attack else "Normal Traffic",
            "confidence": confidence,
            "mlp_confidence": confidence,
            "risk_score": risk,
            "risk_status": sev,
            "threat_level": sev,
            "is_attack": is_attack,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "threat_intel": ti,
            "risk_evidence": risk_res["evidence"],
            "llm_report": llm_report,
            "mitre_technique": llm_report.get("mitre_technique", "N/A"),
            "chess_tactic": f"Adversarial Defense against {attack_type}" if is_attack else "Equilibrium Routine Flow",
            "recommended_action": llm_report.get("recommended_action", "Log and monitor flow")
        }


def main():
    predictor = NetworkPredictor()
    sample_flow = {
        "src_ip": "192.168.56.104",
        "dst_ip": "192.168.56.107",
        "src_port": 49152,
        "dst_port": 4444,
        "protocol": "TCP",
        "packet_length": 1500,
        "flags": "SYN, ACK, PUSH"
    }
    result = predictor.predict_flow(sample_flow)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
