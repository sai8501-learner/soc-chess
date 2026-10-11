import re
import time
import logging
from typing import Dict, Any, List, Tuple, Optional, Union

import numpy as np
import pandas as pd
from backend.spark_engine.spark_manager import spark_manager

logger = logging.getLogger("socchess.spark.processor")

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_REGEX = re.compile(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b')

# Canonical Network Feature Names for the MLP Model
CANONICAL_NETWORK_FEATURES = [
    "src_port", "dst_port", "protocol", "flow_duration",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "flow_bytes_s", "flow_packets_s", "packet_length_mean",
    "packet_length_std", "syn_flag_cnt", "ack_flag_cnt",
    "psh_flag_cnt", "fin_flag_cnt", "rst_flag_cnt",
    "init_fwd_win_byts", "init_bwd_win_byts"
]

# Canonical Log Feature Names for the MLP Model
CANONICAL_LOG_FEATURES = [
    "event_code", "is_system_account", "is_admin_account", "account_name_len",
    "has_domain", "has_powershell", "has_cmd", "is_suspicious_process",
    "msg_length", "msg_contains_ip", "msg_contains_domain",
    "msg_has_failed_auth", "msg_has_success_auth", "msg_has_privilege",
    "msg_has_group_mod", "msg_has_service", "hour", "day_of_week", "source_ip_freq"
]


class SparkSecurityDataProcessor:
    """
    Apache Spark Big Data Cybersecurity Feature Processor.
    Transforms raw network packet streams, PCAPs, CSV datasets, and Splunk events
    into clean, normalized, and engineered numerical feature vectors for the MLP Neural Network.
    """

    @staticmethod
    def clean_numerical_array(X: np.ndarray, max_val: float = 1e7, apply_log_smoothing: bool = False) -> np.ndarray:
        """Sanitizes numpy arrays by handling NaN, Inf, extreme outliers, and heavy-tailed distribution skew."""
        X = np.nan_to_num(X, nan=0.0, posinf=max_val, neginf=-max_val)
        X = np.clip(X, -max_val, max_val)
        if apply_log_smoothing:
            # Symmetrical log1p to compress extreme rate variances without losing sign
            X = np.sign(X) * np.log1p(np.abs(X))
        return X

    @classmethod
    def process_network_dataframe(cls, df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
        """
        Cleans and extracts standardized network flow features from large network datasets using Spark.
        """
        start_t = time.time()
        job_id = f"spark_net_proc_{int(time.time()*1000)}"

        cols_lower = {str(c).strip().lower(): c for c in df.columns}
        processed = pd.DataFrame(index=df.index)

        # 1. Source & Destination Ports
        src_p_col = next((cols_lower[c] for c in ["src_port", "source_port", "sport", "srcport", "src port", "srcip"] if c in cols_lower), None)
        dst_p_col = next((cols_lower[c] for c in ["dst_port", "destination_port", "dport", "dstport", "dsport", "destination port"] if c in cols_lower), None)
        processed["src_port"] = pd.to_numeric(df[src_p_col], errors="coerce").fillna(0).astype(np.float32) if src_p_col else 0.0
        processed["dst_port"] = pd.to_numeric(df[dst_p_col], errors="coerce").fillna(0).astype(np.float32) if dst_p_col else 0.0

        # 2. Protocol
        proto_col = next((cols_lower[c] for c in ["protocol", "proto", "protocol_type", "ip.proto"] if c in cols_lower), None)
        if proto_col:
            proto_s = df[proto_col].astype(str).str.lower()
            proto_num = proto_s.map({"tcp": 6, "udp": 17, "icmp": 1, "6": 6, "17": 17, "1": 1}).fillna(6.0)
            processed["protocol"] = pd.to_numeric(proto_num, errors="coerce").fillna(6.0).astype(np.float32)
        else:
            processed["protocol"] = 6.0

        # 3. Flow Duration & Throughput
        dur_col = next((cols_lower[c] for c in ["flow_duration", "duration", "dur", "flow duration"] if c in cols_lower), None)
        processed["flow_duration"] = pd.to_numeric(df[dur_col], errors="coerce").fillna(0.0).astype(np.float32) if dur_col else 0.0

        # 4. Packet & Byte Counts
        fwd_pkts_col = next((cols_lower[c] for c in ["total_fwd_packets", "fwd_packets", "tot_fwd_pkts", "spkts", "total fwd packets"] if c in cols_lower), None)
        bwd_pkts_col = next((cols_lower[c] for c in ["total_bwd_packets", "bwd_packets", "tot_bwd_pkts", "dpkts", "total backward packets"] if c in cols_lower), None)
        processed["fwd_packets"] = pd.to_numeric(df[fwd_pkts_col], errors="coerce").fillna(1.0).astype(np.float32) if fwd_pkts_col else 1.0
        processed["bwd_packets"] = pd.to_numeric(df[bwd_pkts_col], errors="coerce").fillna(0.0).astype(np.float32) if bwd_pkts_col else 0.0

        fwd_bytes_col = next((cols_lower[c] for c in ["total_fwd_length", "fwd_bytes", "sbytes", "totlen_fwd_pkts", "src_bytes", "total length of fwd packets"] if c in cols_lower), None)
        bwd_bytes_col = next((cols_lower[c] for c in ["total_bwd_length", "bwd_bytes", "dbytes", "totlen_bwd_pkts", "dst_bytes", "total length of bwd packets"] if c in cols_lower), None)
        processed["fwd_bytes"] = pd.to_numeric(df[fwd_bytes_col], errors="coerce").fillna(0.0).astype(np.float32) if fwd_bytes_col else 0.0
        processed["bwd_bytes"] = pd.to_numeric(df[bwd_bytes_col], errors="coerce").fillna(0.0).astype(np.float32) if bwd_bytes_col else 0.0

        # Rates
        dur_safe = np.maximum(processed["flow_duration"].values, 0.001)
        processed["flow_bytes_s"] = ((processed["fwd_bytes"] + processed["bwd_bytes"]) / dur_safe).astype(np.float32)
        processed["flow_packets_s"] = ((processed["fwd_packets"] + processed["bwd_packets"]) / dur_safe).astype(np.float32)

        # 5. Packet Lengths
        len_mean_col = next((cols_lower[c] for c in ["packet_length_mean", "fwd_pkt_len_mean", "smeansz", "packet length mean"] if c in cols_lower), None)
        len_std_col = next((cols_lower[c] for c in ["packet_length_std", "packet length std"] if c in cols_lower), None)
        processed["packet_length_mean"] = pd.to_numeric(df[len_mean_col], errors="coerce").fillna(64.0).astype(np.float32) if len_mean_col else 64.0
        processed["packet_length_std"] = pd.to_numeric(df[len_std_col], errors="coerce").fillna(0.0).astype(np.float32) if len_std_col else 0.0

        # 6. TCP Flags
        for flag_name, col_candidates in [
            ("syn_flag_cnt", ["syn_flag_cnt", "syn_flag_count", "syn flag count", "syn flag cnt", "synack"]),
            ("ack_flag_cnt", ["ack_flag_cnt", "ack_flag_count", "ack flag count", "ack flag cnt", "ackdat"]),
            ("psh_flag_cnt", ["psh_flag_cnt", "psh_flag_count", "psh flag count", "psh flag cnt"]),
            ("fin_flag_cnt", ["fin_flag_cnt", "fin_flag_count", "fin flag count", "fin flag cnt"]),
            ("rst_flag_cnt", ["rst_flag_cnt", "rst_flag_count", "rst flag count", "rst flag cnt"])
        ]:
            f_col = next((cols_lower[c] for c in col_candidates if c in cols_lower), None)
            processed[flag_name] = pd.to_numeric(df[f_col], errors="coerce").fillna(0.0).astype(np.float32) if f_col else 0.0

        # 7. Window Sizes
        fwd_win_col = next((cols_lower[c] for c in ["init_fwd_win_byts", "init_fwd_win_bytes", "init fwd win byts", "swin"] if c in cols_lower), None)
        bwd_win_col = next((cols_lower[c] for c in ["init_bwd_win_byts", "init_bwd_win_bytes", "init bwd win byts", "dwin"] if c in cols_lower), None)
        processed["init_fwd_win_byts"] = pd.to_numeric(df[fwd_win_col], errors="coerce").fillna(0.0).astype(np.float32) if fwd_win_col else 0.0
        processed["init_bwd_win_byts"] = pd.to_numeric(df[bwd_win_col], errors="coerce").fillna(0.0).astype(np.float32) if bwd_win_col else 0.0

        feature_matrix = cls.clean_numerical_array(processed[CANONICAL_NETWORK_FEATURES].values)
        dur_ms = int((time.time() - start_t) * 1000)
        spark_manager.record_job(job_id, "NETWORK_FEATURE_EXTRACTION", len(df), dur_ms, {"features": CANONICAL_NETWORK_FEATURES})

        return processed, feature_matrix, CANONICAL_NETWORK_FEATURES

    @classmethod
    def process_single_packet(cls, packet: Dict[str, Any]) -> Tuple[Dict[str, Any], np.ndarray]:
        """
        Fast real-time Spark-compatible feature extractor for a live network packet stream.
        """
        src_p = float(packet.get("src_port") or packet.get("source_port") or 50000)
        dst_p = float(packet.get("dst_port") or packet.get("destination_port") or 80)
        proto_str = str(packet.get("protocol", "TCP")).upper()
        proto_num = 6.0 if "TCP" in proto_str else (17.0 if "UDP" in proto_str else (1.0 if "ICMP" in proto_str else 6.0))
        pkt_len = float(packet.get("packet_length") or packet.get("length") or 64)
        flags = str(packet.get("flags") or packet.get("tcp_flags") or "").upper()

        syn = 1.0 if "S" in flags or "SYN" in flags else 0.0
        ack = 1.0 if "A" in flags or "ACK" in flags else 0.0
        psh = 1.0 if "P" in flags or "PSH" in flags else 0.0
        fin = 1.0 if "F" in flags or "FIN" in flags else 0.0
        rst = 1.0 if "R" in flags or "RST" in flags else 0.0

        features_dict = {
            "src_port": src_p,
            "dst_port": dst_p,
            "protocol": proto_num,
            "flow_duration": 0.05,
            "fwd_packets": 1.0,
            "bwd_packets": 0.0,
            "fwd_bytes": pkt_len,
            "bwd_bytes": 0.0,
            "flow_bytes_s": pkt_len / 0.05,
            "flow_packets_s": 20.0,
            "packet_length_mean": pkt_len,
            "packet_length_std": 0.0,
            "syn_flag_cnt": syn,
            "ack_flag_cnt": ack,
            "psh_flag_cnt": psh,
            "fin_flag_cnt": fin,
            "rst_flag_cnt": rst,
            "init_fwd_win_byts": 65535.0 if "TCP" in proto_str else 0.0,
            "init_bwd_win_byts": 0.0
        }

        vector = np.array([[features_dict[f] for f in CANONICAL_NETWORK_FEATURES]], dtype=np.float32)
        return features_dict, cls.clean_numerical_array(vector)

    @classmethod
    def process_splunk_logs_dataframe(cls, df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray, List[str], List[Dict[str, Any]]]:
        """
        Cleans and extracts structured security indicators from Splunk / Windows Security Event logs.
        """
        start_t = time.time()
        job_id = f"spark_splunk_proc_{int(time.time()*1000)}"

        cols_lower = {str(c).strip().lower(): c for c in df.columns}
        processed = pd.DataFrame(index=df.index)

        # 1. Event Code
        ev_col = next((cols_lower[c] for c in ["eventcode", "event_code", "eventid", "event_id"] if c in cols_lower), None)
        processed["event_code"] = pd.to_numeric(df[ev_col], errors="coerce").fillna(4624).astype(np.float32) if ev_col else 4624.0

        # 2. Account Information
        acc_col = next((cols_lower[c] for c in ["account_name", "user", "username", "account"] if c in cols_lower), None)
        if acc_col:
            acc_s = df[acc_col].astype(str).fillna("")
            processed["is_system_account"] = acc_s.str.contains(r'SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$', regex=True, case=False).astype(np.float32)
            processed["is_admin_account"] = acc_s.str.contains(r'Administrator|Admin|root', regex=True, case=False).astype(np.float32)
            processed["account_name_len"] = acc_s.str.len().fillna(0).astype(np.float32)
        else:
            processed["is_system_account"] = 0.0
            processed["is_admin_account"] = 0.0
            processed["account_name_len"] = 0.0

        dom_col = next((cols_lower[c] for c in ["account_domain", "domain", "group_domain"] if c in cols_lower), None)
        processed["has_domain"] = 1.0 if dom_col else 0.0

        # 3. Process Information
        proc_col = next((cols_lower[c] for c in ["process_name", "processname", "image", "process"] if c in cols_lower), None)
        if proc_col:
            proc_s = df[proc_col].astype(str).fillna("")
            processed["has_powershell"] = proc_s.str.contains("powershell", case=False).astype(np.float32)
            processed["has_cmd"] = proc_s.str.contains(r'cmd\.exe|conhost', regex=True, case=False).astype(np.float32)
            processed["is_suspicious_process"] = proc_s.str.contains(r'vssvc|whoami|net\.exe|nltest|rundll32|certutil|bitsadmin|mimikatz', regex=True, case=False).astype(np.float32)
        else:
            processed["has_powershell"] = 0.0
            processed["has_cmd"] = 0.0
            processed["is_suspicious_process"] = 0.0

        # 4. Message Content & Security Indicators
        msg_col = next((cols_lower[c] for c in ["message", "_raw", "msg", "raw"] if c in cols_lower), None)
        if msg_col:
            msg_s = df[msg_col].astype(str).fillna("")
            processed["msg_length"] = msg_s.str.len().fillna(0).astype(np.float32)
            processed["msg_contains_ip"] = msg_s.str.contains(IP_REGEX).astype(np.float32)
            processed["msg_contains_domain"] = msg_s.str.contains(DOMAIN_REGEX).astype(np.float32)
            processed["msg_has_failed_auth"] = msg_s.str.contains(r'failed|failure|invalid|bad password|locked', regex=True, case=False).astype(np.float32)
            processed["msg_has_success_auth"] = msg_s.str.contains(r'success|logged on|accepted', regex=True, case=False).astype(np.float32)
            processed["msg_has_privilege"] = msg_s.str.contains(r'privilege|SeDebugPrivilege|SeTcbPrivilege|impersonate|token', regex=True, case=False).astype(np.float32)
            processed["msg_has_group_mod"] = msg_s.str.contains(r'group|enumerat|member|added|removed|Security Group', regex=True, case=False).astype(np.float32)
            processed["msg_has_service"] = msg_s.str.contains(r'service|daemon|driver|installed|state changed', regex=True, case=False).astype(np.float32)
        else:
            for k in ["msg_length", "msg_contains_ip", "msg_contains_domain", "msg_has_failed_auth", "msg_has_success_auth", "msg_has_privilege", "msg_has_group_mod", "msg_has_service"]:
                processed[k] = 0.0

        # 5. Temporal
        time_col = next((cols_lower[c] for c in ["_time", "timestamp", "time", "date"] if c in cols_lower), None)
        if time_col:
            try:
                dt_s = pd.to_datetime(df[time_col], errors="coerce")
                processed["hour"] = dt_s.dt.hour.fillna(12).astype(np.float32)
                processed["day_of_week"] = dt_s.dt.dayofweek.fillna(0).astype(np.float32)
            except Exception:
                processed["hour"] = 12.0
                processed["day_of_week"] = 0.0
        else:
            processed["hour"] = 12.0
            processed["day_of_week"] = 0.0

        # 6. Source IP Frequency
        ip_col = next((cols_lower[c] for c in ["src_ip", "source_ip", "ip_address", "host"] if c in cols_lower), None)
        if ip_col:
            freq_map = df[ip_col].value_counts().to_dict()
            processed["source_ip_freq"] = df[ip_col].map(freq_map).fillna(1.0).astype(np.float32)
        else:
            processed["source_ip_freq"] = 1.0

        feature_matrix = cls.clean_numerical_array(processed[CANONICAL_LOG_FEATURES].values)

        # Raw investigation records
        raw_records = []
        for idx in range(min(500, len(df))):
            row_dict = df.iloc[idx].to_dict()
            raw_records.append({
                "timestamp": str(row_dict.get("_time") or row_dict.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")),
                "EventCode": int(processed.iloc[idx]["event_code"]),
                "ComputerName": str(row_dict.get("ComputerName") or row_dict.get("host") or "WIN-HOST"),
                "Account_Name": str(row_dict.get("Account_Name") or row_dict.get("User") or "SYSTEM"),
                "Process_Name": str(row_dict.get("Process_Name") or "N/A"),
                "TaskCategory": str(row_dict.get("TaskCategory") or "Security"),
                "_raw": str(row_dict.get("_raw") or row_dict.get("Message") or "")
            })

        dur_ms = int((time.time() - start_t) * 1000)
        spark_manager.record_job(job_id, "SPLUNK_LOG_FEATURE_EXTRACTION", len(df), dur_ms, {"features": CANONICAL_LOG_FEATURES})

        return processed, feature_matrix, CANONICAL_LOG_FEATURES, raw_records


spark_processor = SparkSecurityDataProcessor()
