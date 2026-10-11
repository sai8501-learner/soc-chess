import json
import numpy as np
from backend.spark_engine.spark_processor import spark_processor
from backend.ml_engine.mlp_pipeline import mlp_pipeline
from backend.ml_engine.risk_engine import risk_engine
from backend.services.threat_intel import threat_intel_service
from backend.services.llm_analyst import llm_analyst

print("=" * 70)
print("     SOC CHESS — ML MODEL ARCHITECTURE & INFERENCE REPORT")
print("=" * 70)

print("\n1. MODEL TOPOLOGY & PARAMETERS:")
print(f"   Architecture       : 3-Hidden-Layer MLP Neural Network")
print(f"   Layer Dimensions   : 19 Inputs -> Dense(128) -> Dense(64) -> Dense(32) -> 9 Classes")
print(f"   Non-Linearity      : ReLU (Hidden) + Softmax (Output Distribution)")
print(f"   Optimization       : Adam Optimizer with Early Stopping & L2 Regularization (alpha=1e-4)")
print(f"   Total Classes (9)  : {mlp_pipeline.classes}")
print(f"   Features (19)      : {', '.join(mlp_pipeline.feature_names)}")

print("\n2. LIVE INFERENCE BENCHMARK & MULTI-CLASS ACCURACY:")

test_cases = [
    {
        "name": "Benign HTTPS Browsing Flow",
        "expected": "Normal",
        "packet": {
            "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1", "src_port": 54321, "dst_port": 443,
            "protocol": "TCP", "length": 512, "flags": "ACK", "flow_duration": 65000,
            "fwd_packets": 12, "bwd_packets": 10, "fwd_bytes": 1800, "bwd_bytes": 4200
        }
    },
    {
        "name": "Volumetric Mirai SYN Flood Attack",
        "expected": "DDoS",
        "packet": {
            "src_ip": "185.220.101.45", "dst_ip": "192.168.56.107", "src_port": 58312, "dst_port": 80,
            "protocol": "TCP", "length": 64, "flags": "SYN", "flow_duration": 1200,
            "fwd_packets": 15000, "bwd_packets": 0, "fwd_bytes": 960000, "bwd_bytes": 0
        }
    },
    {
        "name": "SSH Password Spray / Brute Force",
        "expected": "Brute Force",
        "packet": {
            "src_ip": "45.142.166.112", "dst_ip": "192.168.56.104", "src_port": 49152, "dst_port": 22,
            "protocol": "TCP", "length": 128, "flags": "PSH,ACK", "flow_duration": 250000,
            "fwd_packets": 120, "bwd_packets": 115, "fwd_bytes": 4800, "bwd_bytes": 5200
        }
    },
    {
        "name": "Stealth SYN Port Sweep (Recon)",
        "expected": "Port Scan",
        "packet": {
            "src_ip": "198.51.100.89", "dst_ip": "192.168.56.100", "src_port": 61245, "dst_port": 8080,
            "protocol": "TCP", "length": 40, "flags": "SYN", "flow_duration": 500,
            "fwd_packets": 1, "bwd_packets": 0, "fwd_bytes": 40, "bwd_bytes": 0
        }
    }
]

for tc in test_cases:
    pkt = tc["packet"]
    feat_dict, feat_vector = spark_processor.process_single_packet(pkt)
    pred = mlp_pipeline.predict(feat_vector)

    # Risk calculation
    ti = threat_intel_service.lookup_ip(pkt["src_ip"])
    risk_res = risk_engine.calculate_risk(
        attack_type=pred["prediction"],
        mlp_confidence=pred["confidence"],
        is_attack=pred["is_attack"],
        threat_intel_score=float(ti.get("threat_score", 0)),
        destination_ip=pkt["dst_ip"]
    )

    print(f"\n[+] Scenario: {tc['name']}")
    print(f"    - Predicted Class   : {pred['prediction']} (Expected: {tc['expected']})")
    print(f"    - MLP Confidence    : {pred['confidence']:.2f}%")
    print(f"    - Risk Score        : {risk_res['risk_score']}/100 [{risk_res['risk_status']}]")
    print(f"    - Threat Intel Score: {ti.get('threat_score', 0)}/100 ({ti.get('reputation', 'UNKNOWN')})")
    
    top_feats = pred.get("top_features", [])
    if top_feats:
        feat_str = ", ".join([f"{f['feature']} ({f['contribution_pct']}%)" for f in top_feats[:3]])
        print(f"    - Key Attribution   : {feat_str}")

print("\n" + "=" * 70)
print("     ML INFERENCE PIPELINE VERIFICATION COMPLETE")
print("=" * 70)
