#!/usr/bin/env python3
"""
SOC CHESS — Network Dataset Merging Utility
Merges all CSV files in datasets/network into a single comprehensive CSV dataset.
Ensures memory safety via streaming buffered I/O, column canonicalization,
and proper handling of headerless datasets (UNSW-NB15 raw, NSL-KDD).
"""

import os
import sys
import csv
import time
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

# Official column schema definitions for headerless datasets
UNSW_OFFICIAL_COLS = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts',
    'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
    'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label'
]

KDD_OFFICIAL_COLS_43 = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'Label', 'difficulty_level'
]

KDD_OFFICIAL_COLS_42 = KDD_OFFICIAL_COLS_43[:-1]

SYNONYM_MAP = {
    'dst_port': ['destination port', 'dst port', 'dport', 'destination_port', 'dst_port', 'dstport', 'dsport'],
    'src_port': ['source port', 'src port', 'sport', 'source_port', 'src_port', 'srcport'],
    'src_ip': ['source ip', 'src ip', 'srcip', 'src_ip', 'source_ip'],
    'dst_ip': ['destination ip', 'dst ip', 'dstip', 'dst_ip', 'destination_ip'],
    'protocol': ['protocol', 'proto', 'protocol_type'],
    'timestamp': ['timestamp', 'stime', 'start time', 'time', 'date', 'last time', 'ltime'],
    'flow_duration': ['flow duration', 'flow_duration', 'dur', 'duration'],
    'tot_fwd_pkts': ['total fwd packets', 'tot fwd pkts', 'spkts', 'total_fwd_packets', 'fwd_packets', 'total_fwd_pkts', 'tot fwd packets'],
    'tot_bwd_pkts': ['total backward packets', 'tot bwd pkts', 'dpkts', 'total_bwd_packets', 'bwd_packets', 'total_bwd_pkts', 'tot bwd packets'],
    'totlen_fwd_pkts': ['total length of fwd packets', 'totlen fwd pkts', 'sbytes', 'src_bytes', 'fwd_bytes', 'totlen fwd packets'],
    'totlen_bwd_pkts': ['total length of bwd packets', 'totlen bwd pkts', 'dbytes', 'dst_bytes', 'bwd_bytes', 'totlen bwd packets'],
    'fwd_pkt_len_max': ['fwd packet length max', 'fwd pkt len max', 'fwd_pkt_len_max'],
    'fwd_pkt_len_min': ['fwd packet length min', 'fwd pkt len min', 'fwd_pkt_len_min'],
    'fwd_pkt_len_mean': ['fwd packet length mean', 'fwd pkt len mean', 'fwd_pkt_len_mean', 'smeansz', 'smean'],
    'fwd_pkt_len_std': ['fwd packet length std', 'fwd pkt len std', 'fwd_pkt_len_std'],
    'bwd_pkt_len_max': ['bwd packet length max', 'bwd pkt len max', 'bwd_pkt_len_max'],
    'bwd_pkt_len_min': ['bwd packet length min', 'bwd pkt len min', 'bwd_pkt_len_min'],
    'bwd_pkt_len_mean': ['bwd packet length mean', 'bwd pkt len mean', 'bwd_pkt_len_mean', 'dmeansz', 'dmean'],
    'bwd_pkt_len_std': ['bwd packet length std', 'bwd pkt len std', 'bwd_pkt_len_std'],
    'flow_byts_s': ['flow bytes/s', 'flow byts/s', 'flow_bytes_s', 'rate', 'sload', 's_load'],
    'flow_pkts_s': ['flow packets/s', 'flow pkts/s', 'flow_packets_s'],
    'flow_iat_mean': ['flow iat mean', 'flow_iat_mean', 'sintpkt', 'dintpkt', 'sinpkt', 'dinpkt'],
    'flow_iat_std': ['flow iat std', 'flow_iat_std'],
    'flow_iat_max': ['flow iat max', 'flow_iat_max'],
    'flow_iat_min': ['flow iat min', 'flow_iat_min'],
    'fwd_iat_tot': ['fwd iat total', 'fwd iat tot', 'fwd_iat_total', 'sjit', 'sinjit'],
    'fwd_iat_mean': ['fwd iat mean', 'fwd_iat_mean'],
    'fwd_iat_std': ['fwd iat std', 'fwd_iat_std'],
    'fwd_iat_max': ['fwd iat max', 'fwd_iat_max'],
    'fwd_iat_min': ['fwd iat min', 'fwd_iat_min'],
    'bwd_iat_tot': ['bwd iat total', 'bwd iat tot', 'bwd_iat_total', 'djit', 'dinjit'],
    'bwd_iat_mean': ['bwd iat mean', 'bwd_iat_mean'],
    'bwd_iat_std': ['bwd iat std', 'bwd_iat_std'],
    'bwd_iat_max': ['bwd iat max', 'bwd_iat_max'],
    'bwd_iat_min': ['bwd iat min', 'bwd_iat_min'],
    'fwd_psh_flags': ['fwd psh flags', 'fwd_psh_flags'],
    'bwd_psh_flags': ['bwd psh flags', 'bwd_psh_flags'],
    'fwd_urg_flags': ['fwd urg flags', 'fwd_urg_flags'],
    'bwd_urg_flags': ['bwd urg flags', 'bwd_urg_flags'],
    'fwd_header_len': ['fwd header length', 'fwd header len', 'fwd_header_len'],
    'bwd_header_len': ['bwd header length', 'bwd header len', 'bwd_header_len'],
    'fwd_pkts_s': ['fwd packets/s', 'fwd pkts/s', 'fwd_packets_per_sec'],
    'bwd_pkts_s': ['bwd packets/s', 'bwd pkts/s', 'bwd_packets_per_sec'],
    'pkt_len_min': ['min packet length', 'pkt len min', 'pkt_len_min'],
    'pkt_len_max': ['max packet length', 'pkt len max', 'pkt_len_max'],
    'pkt_len_mean': ['packet length mean', 'pkt len mean', 'packet_len', 'pkt_len_mean', 'packet_length_mean'],
    'pkt_len_std': ['packet length std', 'pkt len std', 'pkt_len_std'],
    'pkt_len_var': ['packet length variance', 'pkt len var', 'pkt_len_var'],
    'fin_flag_cnt': ['fin flag count', 'fin flag cnt', 'fin_flag_count'],
    'syn_flag_cnt': ['syn flag count', 'syn flag cnt', 'syn_flag_count', 'syn_count', 'synack'],
    'rst_flag_cnt': ['rst flag count', 'rst flag cnt', 'rst_flag_count'],
    'psh_flag_cnt': ['psh flag count', 'psh flag cnt', 'psh_flag_count'],
    'ack_flag_cnt': ['ack flag count', 'ack flag cnt', 'ack_flag_count', 'ackdat'],
    'urg_flag_cnt': ['urg flag count', 'urg flag cnt', 'urg_flag_count'],
    'cwe_flag_cnt': ['cwe flag count', 'cwe flag cnt', 'cwe_flag_count'],
    'ece_flag_cnt': ['ece flag count', 'ece flag cnt', 'ece_flag_count'],
    'down_up_ratio': ['down/up ratio', 'down_up_ratio'],
    'pkt_size_avg': ['average packet size', 'pkt size avg', 'avg_packet_size'],
    'fwd_seg_size_avg': ['avg fwd segment size', 'fwd seg size avg'],
    'bwd_seg_size_avg': ['avg bwd segment size', 'bwd seg size avg'],
    'init_fwd_win_byts': ['init_win_bytes_forward', 'init fwd win byts', 'swin', 'init_fwd_win_bytes'],
    'init_bwd_win_byts': ['init_win_bytes_backward', 'init bwd win byts', 'dwin', 'init_bwd_win_bytes'],
    'active_mean': ['active mean', 'active_mean'],
    'active_std': ['active std', 'active_std'],
    'active_max': ['active max', 'active_max'],
    'active_min': ['active min', 'active_min'],
    'idle_mean': ['idle mean', 'idle_mean'],
    'idle_std': ['idle std', 'idle_std'],
    'idle_max': ['idle max', 'idle_max'],
    'idle_min': ['idle min', 'idle_min'],
    'attack_cat': ['attack category', 'attack_cat', 'attack name', 'attack subcategory', 'label_name'],
    'label': ['label', 'target', 'class', 'verdict', 'attack']
}

LOOKUP = {}
for canon, syns in SYNONYM_MAP.items():
    for s in syns:
        LOOKUP[s.lower().strip()] = canon
        LOOKUP[s.lower().replace(' ', '_').strip()] = canon
        LOOKUP[s.lower().replace(' ', '').strip()] = canon

def get_canonical(col: str) -> str:
    col_str = str(col).strip().strip('\ufeff')
    c_low = col_str.lower()
    if c_low in LOOKUP: return LOOKUP[c_low]
    c_under = c_low.replace(' ', '_').replace('-', '_')
    if c_under in LOOKUP: return LOOKUP[c_under]
    c_nospace = re.sub(r'[^a-z0-9]', '', c_low)
    if c_nospace in LOOKUP: return LOOKUP[c_nospace]
    return col_str

# Preferred column ordering for standard flow features
PRIORITY_COLS = [
    'source_file', 'label', 'attack_cat', 'protocol', 'src_ip', 'src_port',
    'dst_ip', 'dst_port', 'timestamp', 'flow_duration', 'tot_fwd_pkts',
    'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_mean',
    'bwd_pkt_len_mean', 'pkt_len_mean', 'flow_byts_s', 'flow_pkts_s',
    'flow_iat_mean', 'syn_flag_cnt', 'ack_flag_cnt', 'fin_flag_cnt',
    'rst_flag_cnt', 'psh_flag_cnt', 'urg_flag_cnt', 'init_fwd_win_byts',
    'init_bwd_win_byts', 'active_mean', 'idle_mean'
]

def merge_all_network_csvs(
    network_dir: Path,
    output_csv_path: Path,
    chunk_size: int = 100000
) -> Dict[str, Any]:
    print("=" * 80)
    print("  SOC CHESS — MERGING ALL NETWORK DATASET CSV FILES INTO SINGLE CSV")
    print("=" * 80)
    print(f"[*] Input directory:  {network_dir.resolve()}")
    print(f"[*] Output CSV path:  {output_csv_path.resolve()}")
    
    # 1. Discover all CSV files
    all_files = sorted([
        f for f in network_dir.glob("*.csv")
        if not f.name.startswith("merged_") and f.resolve() != output_csv_path.resolve()
    ])
    
    if not all_files:
        raise FileNotFoundError(f"No CSV files found in {network_dir}")
    
    print(f"[+] Found {len(all_files)} CSV files in network directory:\n")
    for idx, f in enumerate(all_files, 1):
        sz_mb = f.stat().st_size / (1024 * 1024)
        print(f"  {idx:2d}. {f.name:<60} ({sz_mb:8.2f} MB)")
    print("-" * 80)
    
    # 2. First Pass: Analyze schemas and build global canonical header
    print("[*] Stage 1/2: Analyzing schemas across all files...")
    all_canon_cols_set = set()
    file_schemas = {}

    for f in all_files:
        f_low = f.name.lower()
        if f_low.startswith("unsw-nb15_") and len(f_low) > 10 and f_low[10].isdigit():
            # UNSW raw flow files (no header)
            cols = UNSW_OFFICIAL_COLS
            has_header = False
            sep = ','
        elif "kdd" in f_low:
            # NSL-KDD tab-separated (no header)
            with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                first_line = fp.readline().strip()
            num_tokens = len(first_line.split('\t'))
            cols = KDD_OFFICIAL_COLS_43 if num_tokens >= 43 else KDD_OFFICIAL_COLS_42
            has_header = False
            sep = '\t'
        else:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                first_line = fp.readline().strip()
            sep = '\t' if ('\t' in first_line and first_line.count('\t') > first_line.count(',')) else ','
            cols = [c.strip().strip('\ufeff') for c in first_line.split(sep)]
            has_header = True
        
        canon_cols = [get_canonical(c) for c in cols]
        for c in canon_cols:
            all_canon_cols_set.add(c)
        
        file_schemas[f.name] = {
            'path': f,
            'sep': sep,
            'has_header': has_header,
            'raw_cols': cols,
            'canon_cols': canon_cols
        }

    # Build ordered global header: Priority columns first, then remaining sorted
    global_header = ['source_file']
    for pc in PRIORITY_COLS:
        if pc in all_canon_cols_set and pc not in global_header:
            global_header.append(pc)
    
    remaining_cols = sorted([c for c in all_canon_cols_set if c not in global_header])
    global_header.extend(remaining_cols)
    
    header_index_map = {col_name: i for i, col_name in enumerate(global_header)}
    total_cols = len(global_header)
    print(f"[+] Schema analysis complete: Unified dataset contains {total_cols} canonical columns.")
    print("-" * 80)
    
    # 3. Stage 2: Stream all CSVs into single merged output
    print(f"[*] Stage 2/2: Streaming and merging data into {output_csv_path.name}...")
    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    
    start_time = time.time()
    total_records = 0
    file_record_counts = {}

    with open(output_csv_path, 'w', newline='', encoding='utf-8', buffering=1024*1024*8) as out_fp:
        writer = csv.writer(out_fp)
        writer.writerow(global_header)
        
        for file_idx, f in enumerate(all_files, 1):
            f_meta = file_schemas[f.name]
            f_path = f_meta['path']
            sep = f_meta['sep']
            has_header = f_meta['has_header']
            canon_cols = f_meta['canon_cols']
            
            # Map input column positions to output global_header indices
            col_target_indices = [header_index_map.get(col, -1) for col in canon_cols]
            
            f_start = time.time()
            f_records = 0
            
            with open(f_path, 'r', encoding='utf-8', errors='ignore', buffering=1024*1024*4) as in_fp:
                reader = csv.reader(in_fp, delimiter=sep)
                
                if has_header:
                    next(reader, None)  # skip header row
                
                batch = []
                for row in reader:
                    if not row:
                        continue
                    # Create blank unified row initialized to empty string
                    out_row = [''] * total_cols
                    out_row[0] = f.name  # source_file
                    
                    row_len = len(row)
                    for src_idx, tgt_idx in enumerate(col_target_indices):
                        if tgt_idx != -1 and src_idx < row_len:
                            out_row[tgt_idx] = row[src_idx].strip()
                    
                    batch.append(out_row)
                    f_records += 1
                    
                    if len(batch) >= chunk_size:
                        writer.writerows(batch)
                        batch.clear()
                
                if batch:
                    writer.writerows(batch)
                    batch.clear()
            
            total_records += f_records
            file_record_counts[f.name] = f_records
            f_dur = time.time() - f_start
            f_rate = (f_records / f_dur) if f_dur > 0 else 0
            print(f"  [{file_idx:2d}/{len(all_files)}] Merged {f.name:<55} -> {f_records:10,d} rows ({f_rate:8,.0f} rows/s)")
    
    total_elapsed = time.time() - start_time
    output_size_bytes = output_csv_path.stat().st_size
    output_size_gb = output_size_bytes / (1024 ** 3)
    
    print("=" * 80)
    print("  MERGE COMPLETE — SUMMARY REPORT")
    print("=" * 80)
    print(f"[*] Target File:       {output_csv_path.resolve()}")
    print(f"[*] Total Rows:        {total_records:,d} data records (+ 1 header row)")
    print(f"[*] Total Columns:     {total_cols} canonical features")
    print(f"[*] Final File Size:   {output_size_gb:.2f} GB ({output_size_bytes:,d} bytes)")
    print(f"[*] Total Time Taken:  {total_elapsed:.1f} seconds ({(total_records/total_elapsed):,.0f} rows/second)")
    print("=" * 80)

    return {
        'status': 'success',
        'output_file': str(output_csv_path.resolve()),
        'total_records': total_records,
        'total_columns': total_cols,
        'size_gb': round(output_size_gb, 2),
        'elapsed_sec': round(total_elapsed, 1),
        'file_record_counts': file_record_counts
    }

if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    net_dir = base_dir / "datasets" / "network"
    output_csv = base_dir / "datasets" / "network_merged_all.csv"
    
    if len(sys.argv) > 1:
        net_dir = Path(sys.argv[1])
    if len(sys.argv) > 2:
        output_csv = Path(sys.argv[2])
    
    merge_all_network_csvs(net_dir, output_csv)
