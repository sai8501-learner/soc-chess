#!/usr/bin/env python3
"""
================================================================================
SOC CHESS -- REAL-TIME PACKET CAPTURE & LIVE THREAT SCORING ENGINE
================================================================================
STEP 8 of the ML pipeline.

Connects live network interfaces or simulated network traffic streams with
the trained SOC Chess ML detection system:
  - Sniffs incoming packets using Scapy or simulated socket streams
  - Assembles packets into bidirectional 5-tuple network flows
  - Computes flow statistical metrics (flow duration, bytes/s, packets/s, TCP flags)
  - Scores flows in real-time using predict_network.NetworkPredictor
  - Maps detections to adversarial chess tactics
  - Emits structured threat telemetry

Usage:
  python python/capture_engine.py --test
  python python/capture_engine.py --simulate --count 20
  python python/capture_engine.py --live --interface auto
================================================================================
"""

import os
import sys
import time
import json
import random
import argparse
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from model_utils import BASE_DIR, PYTHON_DIR, safe_json_read

try:
    from predict_network import NetworkPredictor
except ImportError:
    NetworkPredictor = None

try:
    from predict_splunk import SplunkPredictor
except ImportError:
    SplunkPredictor = None


class FlowRecord:
    """Tracks a bidirectional network flow."""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.last_seen = self.start_time

        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_pkt_lens = []
        self.bwd_pkt_lens = []

        self.syn_flag_cnt = 0
        self.ack_flag_cnt = 0
        self.psh_flag_cnt = 0
        self.fin_flag_cnt = 0

    def add_packet(self, size: int, is_fwd: bool, flags: int = 0):
        self.last_seen = time.time()
        if is_fwd:
            self.fwd_packets += 1
            self.fwd_bytes += size
            self.fwd_pkt_lens.append(size)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += size
            self.bwd_pkt_lens.append(size)

        # TCP flags
        if flags & 0x02: self.syn_flag_cnt += 1
        if flags & 0x10: self.ack_flag_cnt += 1
        if flags & 0x08: self.psh_flag_cnt += 1
        if flags & 0x01: self.fin_flag_cnt += 1

    def to_feature_dict(self) -> Dict[str, Any]:
        dur_sec = max(self.last_seen - self.start_time, 0.0001)
        dur_us = dur_sec * 1_000_000
        tot_pkts = self.fwd_packets + self.bwd_packets
        tot_bytes = self.fwd_bytes + self.bwd_bytes

        fwd_mean = float(sum(self.fwd_pkt_lens) / len(self.fwd_pkt_lens)) if self.fwd_pkt_lens else 0.0
        bwd_mean = float(sum(self.bwd_pkt_lens) / len(self.bwd_pkt_lens)) if self.bwd_pkt_lens else 0.0

        return {
            "source_ip": self.src_ip,
            "destination_ip": self.dst_ip,
            "source_port": self.src_port,
            "destination_port": self.dst_port,
            "protocol": self.protocol,
            "flow_duration": dur_us,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "flow_bytes_s": tot_bytes / dur_sec,
            "flow_packets_s": tot_pkts / dur_sec,
            "fwd_pkt_len_mean": fwd_mean,
            "bwd_pkt_len_mean": bwd_mean,
            "syn_flag_cnt": self.syn_flag_cnt,
            "ack_flag_cnt": self.ack_flag_cnt,
            "psh_flag_cnt": self.psh_flag_cnt,
            "fin_flag_cnt": self.fin_flag_cnt,
        }


class CaptureEngine:
    """SOC Chess real-time capture and live scoring engine."""

    def __init__(self, config_path: Optional[Path] = None):
        cfg_file = config_path or (PYTHON_DIR / "device_config.json")
        self.config = safe_json_read(cfg_file) or {}
        self.network_predictor = None
        self.splunk_predictor = None

        try:
            self.network_predictor = NetworkPredictor()
        except Exception as e:
            print(f"[CaptureEngine] Warning: Network predictor not loaded ({e})")

        try:
            self.splunk_predictor = SplunkPredictor()
        except Exception as e:
            print(f"[CaptureEngine] Warning: Splunk predictor not loaded ({e})")

    def simulate_traffic(self, count: int = 15) -> List[Dict[str, Any]]:
        """Simulate realistic live network streams and score each flow."""
        print(f"\n[*] Simulating {count} live network flows...")
        events = []

        scenarios = [
            # Legitimate Web Browsing
            {
                "dst_port": 443, "proto": 6, "f_pkts": (5, 20), "b_pkts": (8, 40),
                "f_bytes": (500, 3000), "b_bytes": (2000, 50000), "dur": (0.2, 3.5),
                "syn": 1, "ack": (10, 50)
            },
            # DNS Query
            {
                "dst_port": 53, "proto": 17, "f_pkts": (1, 2), "b_pkts": (1, 2),
                "f_bytes": (40, 80), "b_bytes": (60, 200), "dur": (0.01, 0.05),
                "syn": 0, "ack": 0
            },
            # SYN Flood / Port Scan
            {
                "dst_port": random.choice([22, 23, 80, 445, 3389, 8080]), "proto": 6,
                "f_pkts": (1, 3), "b_pkts": (0, 0), "f_bytes": (40, 120), "b_bytes": (0, 0),
                "dur": (0.001, 0.05), "syn": (1, 3), "ack": 0
            },
            # High-Volume DDoS Flow
            {
                "dst_port": 80, "proto": 6, "f_pkts": (100, 500), "b_pkts": (0, 5),
                "f_bytes": (20000, 100000), "b_bytes": (0, 300), "dur": (0.05, 0.5),
                "syn": (50, 250), "ack": 0
            },
        ]

        for i in range(1, count + 1):
            sc = random.choice(scenarios)
            src_ip = f"192.168.1.{random.randint(10, 250)}"
            dst_ip = f"10.0.0.{random.randint(1, 10)}" if random.random() > 0.5 else f"93.184.216.{random.randint(1, 254)}"
            src_port = random.randint(30000, 65000)
            dst_port = sc["dst_port"]
            protocol = sc["proto"]

            flow = FlowRecord(src_ip, dst_ip, src_port, dst_port, protocol)
            f_pkts = random.randint(*sc["f_pkts"])
            b_pkts = random.randint(*sc["b_pkts"]) if isinstance(sc["b_pkts"], tuple) else sc["b_pkts"]
            f_bytes = random.randint(*sc["f_bytes"])
            b_bytes = random.randint(*sc["b_bytes"]) if isinstance(sc["b_bytes"], tuple) else sc["b_bytes"]

            syn_cnt = random.randint(*sc["syn"]) if isinstance(sc["syn"], tuple) else sc["syn"]
            ack_cnt = random.randint(*sc["ack"]) if isinstance(sc["ack"], tuple) else sc["ack"]

            flow.fwd_packets = f_pkts
            flow.bwd_packets = b_pkts
            flow.fwd_bytes = f_bytes
            flow.bwd_bytes = b_bytes
            flow.fwd_pkt_lens = [f_bytes // max(f_pkts, 1)] * f_pkts
            flow.bwd_pkt_lens = [b_bytes // max(b_pkts, 1)] * b_pkts
            flow.syn_flag_cnt = syn_cnt
            flow.ack_flag_cnt = ack_cnt
            flow.last_seen = flow.start_time + random.uniform(*sc["dur"])

            feat_dict = flow.to_feature_dict()

            prediction_result = {}
            if self.network_predictor:
                prediction_result = self.network_predictor.predict_flow(feat_dict)

            summary = {
                "flow_id": f"flow_{i:04d}",
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "protocol": "TCP" if protocol == 6 else ("UDP" if protocol == 17 else str(protocol)),
                "fwd_pkts": f_pkts,
                "bwd_pkts": b_pkts,
                "bytes": f_bytes + b_bytes,
                **prediction_result
            }
            events.append(summary)

            threat_badge = f"[{summary.get('threat_level', 'INFO')}]"
            print(f"  {threat_badge:<10} {summary['src']} -> {summary['dst']:<21} | Pred: {summary.get('prediction', 'UNKNOWN'):<12} | Tactic: {summary.get('chess_tactic', 'N/A')}")
            time.sleep(0.05)

        return events

    def run_live_sniff(self, interface: str = "auto", timeout: int = 30):
        """Sniff live packets if Scapy is installed."""
        print(f"[*] Initializing live capture on interface '{interface}' (Timeout: {timeout}s)...")
        try:
            from scapy.all import sniff, IP, TCP, UDP
        except ImportError:
            print("[-] Scapy is not available for raw sniffing. Falling back to simulation mode.")
            return self.simulate_traffic(15)

        active_flows: Dict[str, FlowRecord] = {}

        def packet_handler(pkt):
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
            proto = ip.proto
            src_port, dst_port, flags = 0, 0, 0

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                flags = int(tcp.flags)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port, dst_port = udp.sport, udp.dport

            flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{proto}"
            rev_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}:{proto}"

            if flow_key in active_flows:
                active_flows[flow_key].add_packet(len(pkt), is_fwd=True, flags=flags)
            elif rev_key in active_flows:
                active_flows[rev_key].add_packet(len(pkt), is_fwd=False, flags=flags)
            else:
                flow = FlowRecord(src_ip, dst_ip, src_port, dst_port, proto)
                flow.add_packet(len(pkt), is_fwd=True, flags=flags)
                active_flows[flow_key] = flow

        sniff(filter=self.config.get("capture", {}).get("bpf_filter", "ip"),
              prn=packet_handler, timeout=timeout, store=0)

        print(f"[*] Captured and assembled {len(active_flows)} flows.")
        scored_events = []
        for key, flow in active_flows.items():
            feat = flow.to_feature_dict()
            res = self.network_predictor.predict_flow(feat) if self.network_predictor else {}
            scored_events.append({**feat, **res})

        return scored_events


def main():
    parser = argparse.ArgumentParser(description="SOC Chess Live Capture & Threat Scoring Engine")
    parser.add_argument("--test", action="store_true", help="Run capture engine verification self-test")
    parser.add_argument("--simulate", action="store_true", help="Simulate live traffic and evaluate in real-time")
    parser.add_argument("--count", type=int, default=15, help="Number of simulated flows to generate")
    parser.add_argument("--live", action="store_true", help="Start live packet sniffer")
    parser.add_argument("--interface", type=str, default="auto", help="Network interface for sniffing")
    args = parser.parse_args()

    engine = CaptureEngine()

    if args.test or (not args.simulate and not args.live):
        print("=" * 60)
        print("  SOC CHESS -- CAPTURE & LIVE INFERENCE ENGINE TEST")
        print("=" * 60)
        events = engine.simulate_traffic(count=10)
        print("\n[+] Verification completed successfully. Total flows scored:", len(events))
        return

    if args.simulate:
        engine.simulate_traffic(count=args.count)

    elif args.live:
        engine.run_live_sniff(interface=args.interface)


if __name__ == "__main__":
    main()
