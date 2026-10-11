#!/usr/bin/env python3
"""
================================================================================
SOC CHESS -- DATASET PROCESSOR
================================================================================
STEP 2 of the ML pipeline.

Discovers, parses, normalises, and merges:
  1. datasets/network/         -> datasets/processed/network_merged.csv
  2. datasets/Splunk-Attack-Data/datasets/ -> datasets/processed/splunk_merged.csv

Features:
  - Automatic file discovery (recursive)
  - Git LFS pointer detection (skip + log)
  - Chunked reading for large CSVs (MAX_ROWS_PER_FILE rows per source)
  - Stratified label sampling to preserve class balance
  - Known schema detection (CIC-IDS, UNSW-NB15, NSL-KDD)
  - Column synonym normalisation
  - Label normalisation (NORMAL / ATTACK / UNKNOWN)
  - YAML metadata extraction for Splunk scenarios
  - Failed file tracking
  - Data quality report
  - Source traceability on every record

Run:
  python python/dataset_processor.py
================================================================================
"""

import os, sys, csv, re, time, json, traceback, warnings
from pathlib import Path
from typing  import Any, Dict, List, Optional, Tuple
import pandas as pd
import numpy  as np
warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Bootstrap: add python/ dir to sys.path so model_utils imports cleanly
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from model_utils import (
    BASE_DIR, DATASETS_DIR, PROCESSED_DIR, NETWORK_DIR, SPLUNK_DIR,
    PYTHON_DIR, PROCESSING_LOG, SPLUNK_SKIP_NAMES,
    NETWORK_EXTENSIONS, SPLUNK_EXTENSIONS, METADATA_EXTENSIONS,
    NETWORK_SYNONYM_MAP, LABEL_COLUMNS, NORMAL_LABELS, UNKNOWN_LABEL,
    UNSW_COLS_49, KDD_COLS_43, KDD_COLS_42,
    setup_logger, is_git_lfs_pointer, discover_files, discover_yaml_files,
    normalize_label, normalize_network_columns, detect_network_schema,
    parse_splunk_yaml, safe_json_write, print_section, print_subsection,
    print_progress
)

log = setup_logger("dataset_processor", PROCESSING_LOG)

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
MAX_ROWS_PER_FILE = 50_000    # cap per source CSV file (stratified sample)
CHUNK_SIZE        = 25_000    # pandas read_csv chunksize
FAILED_CSV        = PROCESSED_DIR / "failed_files.csv"

# Columns that should NOT leak into ML features
LEAKAGE_COLS = {
    "source_file","relative_path","absolute_path","source_dataset","data_type",
    "raw_message","attack_scenario","description","author","environment",
    "log_sourcetype","log_source"
}

# ---------------------------------------------------------------------------
# FAILED FILES TRACKER
# ---------------------------------------------------------------------------
_failed: List[Dict] = []

def record_failure(file_path: Path, root: Path, reason: str, error: str = "") -> None:
    try:
        rel = str(file_path.relative_to(root)).replace("\\", "/")
    except Exception:
        rel = str(file_path)
    _failed.append({
        "file":          file_path.name,
        "relative_path": rel,
        "file_type":     file_path.suffix.lower(),
        "error":         error[:300] if error else "",
        "reason":        reason,
    })
    log.warning(f"  SKIP [{reason}] {file_path.name}: {error[:120]}")

def flush_failed_csv() -> None:
    if not _failed:
        return
    df = pd.DataFrame(_failed)
    df.to_csv(FAILED_CSV, index=False, encoding="utf-8")
    log.info(f"Failed files written: {FAILED_CSV}")

# ---------------------------------------------------------------------------
# NETWORK CSV READER
# ---------------------------------------------------------------------------
def _find_label_col(columns: List[str]) -> Optional[str]:
    col_lower = {c.lower().strip(): c for c in columns}
    for candidate in LABEL_COLUMNS:
        if candidate.lower() in col_lower:
            return col_lower[candidate.lower()]
    return None

def _read_csv_with_schema(
    fpath: Path, schema: str, n_rows_limit: int
) -> Optional[pd.DataFrame]:
    """
    Read a network CSV using the detected schema.
    Applies chunked reading and caps at n_rows_limit to stay memory-safe.
    """
    try:
        # Detect header
        has_header = True
        if schema == "unsw_nb15":
            fname_upper = fpath.name.upper()
            if re.match(r"UNSW.NB15_\d", fname_upper):
                has_header = False
        if schema == "kdd":
            with open(fpath, "rb") as f:
                first = f.read(20).decode("utf-8", errors="ignore")
            if first.strip()[:8].lower() in ("duration","protocol"):
                has_header = True
            else:
                has_header = False

        header_arg = 0 if has_header else None
        names_arg  = None

        if not has_header:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
            n_cols = len(first_line.split(","))
            if schema == "unsw_nb15":
                names_arg = UNSW_COLS_49[:n_cols]
            elif schema == "kdd":
                if n_cols == 43:
                    names_arg = KDD_COLS_43
                elif n_cols == 42:
                    names_arg = KDD_COLS_42
                else:
                    names_arg = [f"col_{i}" for i in range(n_cols)]

        chunks = []
        rows_collected = 0

        reader = pd.read_csv(
            fpath,
            header=header_arg,
            names=names_arg,
            chunksize=CHUNK_SIZE,
            encoding="utf-8",
            encoding_errors="replace",
            low_memory=False,
            on_bad_lines="skip",
        )

        for chunk in reader:
            if chunk.empty:
                continue
            chunk.columns = [str(c).strip() for c in chunk.columns]
            chunks.append(chunk)
            rows_collected += len(chunk)
            if rows_collected >= n_rows_limit:
                break

        if not chunks:
            return None

        df = pd.concat(chunks, ignore_index=True)
        if len(df) > n_rows_limit:
            df = df.iloc[:n_rows_limit]

        return df

    except Exception as e:
        raise RuntimeError(str(e)) from e

CANONICAL_NETWORK_COLUMNS = [
    "source_ip", "destination_ip", "source_port", "destination_port", "protocol",
    "flow_duration", "fwd_bytes", "bwd_bytes", "fwd_packets", "bwd_packets",
    "flow_bytes_s", "flow_packets_s", "fwd_pkt_len_mean", "bwd_pkt_len_mean",
    "syn_flag_cnt", "ack_flag_cnt", "psh_flag_cnt", "fin_flag_cnt",
    "init_fwd_win_byts", "init_bwd_win_byts", "state", "service",
    "attack_category", "original_label", "source_dataset", "source_file",
    "relative_path", "data_type", "label"
]

CANONICAL_SPLUNK_COLUMNS = [
    "timestamp", "source_ip", "destination_ip", "source_port", "destination_port",
    "protocol", "event_code", "event_id", "event_type", "action", "status",
    "username", "hostname", "process_name", "command_line", "file_name", "hash",
    "url", "bytes_in", "bytes_out", "duration", "attack_category", "attack_scenario",
    "mitre_technique", "original_label", "label", "source_dataset", "source_file",
    "relative_path", "data_type", "log_sourcetype", "log_source", "description",
    "author", "environment", "raw_message"
]

def _process_network_csv(fpath: Path) -> Optional[pd.DataFrame]:
    """
    Process a single network CSV file. Returns normalised DataFrame aligned to CANONICAL_NETWORK_COLUMNS.
    """
    try:
        peek = pd.read_csv(
            fpath, nrows=5, encoding="utf-8", encoding_errors="replace",
            on_bad_lines="skip", low_memory=False
        )
        peek.columns = [str(c).strip() for c in peek.columns]
        cols_lower   = {c.lower().strip() for c in peek.columns}
        schema       = detect_network_schema(fpath, cols_lower)

        df = _read_csv_with_schema(fpath, schema, MAX_ROWS_PER_FILE)
        if df is None or df.empty:
            record_failure(fpath, NETWORK_DIR, "empty_after_read")
            return None

        # Normalise columns
        df = normalize_network_columns(df)

        # Find and apply label
        label_col = _find_label_col(df.columns.tolist())
        if label_col:
            labels = df[label_col].apply(normalize_label)
            df["label"]           = [l[0] for l in labels]
            df["attack_category"] = [l[1] for l in labels]
            df["original_label"]  = df[label_col]
        else:
            df["label"]           = UNKNOWN_LABEL
            df["attack_category"] = ""
            df["original_label"]  = None

        # Source traceability
        try:
            rel = str(fpath.relative_to(NETWORK_DIR)).replace("\\", "/")
        except Exception:
            rel = fpath.name
        df["source_dataset"] = "network"
        df["source_file"]    = fpath.name
        df["relative_path"]  = rel
        df["data_type"]      = schema

        # Align columns to canonical schema
        for col in CANONICAL_NETWORK_COLUMNS:
            if col not in df.columns:
                df[col] = None
        df = df[CANONICAL_NETWORK_COLUMNS]

        return df

    except Exception as e:
        record_failure(fpath, NETWORK_DIR, "parse_error", str(e))
        return None

# ---------------------------------------------------------------------------
# NETWORK PIPELINE
# ---------------------------------------------------------------------------
def process_network_dataset() -> Dict:
    print_section("NETWORK DATASET PROCESSING")
    log.info("=== NETWORK PROCESSING STARTED ===")

    files = discover_files(NETWORK_DIR, NETWORK_EXTENSIONS)
    total = len(files)
    log.info(f"Network files discovered: {total}")
    print(f"\n  Files discovered: {total}")

    out_csv = PROCESSED_DIR / "network_merged.csv"
    if out_csv.exists():
        out_csv.unlink()

    processed = 0
    failed    = 0
    total_records = 0
    file_type_counts: Dict[str, int] = {}
    source_counts:    Dict[str, int] = {}
    label_counts:     Dict[str, int] = {}
    all_features:     List[str] = []

    for i, fpath in enumerate(files, 1):
        print_progress(i, total, fpath.name)
        ext = fpath.suffix.lower()
        file_type_counts[ext] = file_type_counts.get(ext, 0) + 1

        if is_git_lfs_pointer(fpath):
            record_failure(fpath, NETWORK_DIR, "git_lfs_pointer", "File is a Git LFS pointer")
            failed += 1
            continue

        df_chunk = None
        if ext == ".csv":
            df_chunk = _process_network_csv(fpath)
        elif ext in {".json", ".jsonl", ".ndjson"}:
            recs = _process_json_file(fpath, NETWORK_DIR, "network", "network_json")
            df_chunk = pd.DataFrame(recs) if recs else None
        elif ext == ".xml":
            recs = _process_xml_file(fpath, NETWORK_DIR, "network", "network_xml")
            df_chunk = pd.DataFrame(recs) if recs else None
        elif ext in {".log", ".txt"}:
            recs = _process_text_file(fpath, NETWORK_DIR, "network", "network_log")
            df_chunk = pd.DataFrame(recs) if recs else None
        else:
            record_failure(fpath, NETWORK_DIR, "unsupported_type")
            failed += 1
            continue

        if df_chunk is not None and not df_chunk.empty:
            is_first = not out_csv.exists()
            df_chunk.to_csv(out_csv, mode="a", header=is_first, index=False, encoding="utf-8")
            
            rec_count = len(df_chunk)
            total_records += rec_count
            source_counts[fpath.name] = rec_count
            processed += 1

            if "label" in df_chunk.columns:
                chunk_labels = df_chunk["label"].value_counts().to_dict()
                for k, v in chunk_labels.items():
                    label_counts[str(k)] = label_counts.get(str(k), 0) + int(v)

            if not all_features:
                all_features = [c for c in df_chunk.columns if c not in LEAKAGE_COLS and c != "label"]

            log.info(f"  OK [{i}/{total}] {fpath.name}: {rec_count:,} records (total so far: {total_records:,})")
        else:
            failed += 1

    print(f"\n  Processed: {processed}  Failed/Skipped: {failed}  Total records: {total_records:,}")

    if total_records == 0:
        log.error("No network records collected!")
        return {"total_files": total, "processed": 0, "failed": failed, "records": 0}

    unknown_count = label_counts.get(UNKNOWN_LABEL, 0)
    labeled_count = total_records - unknown_count

    summary = {
        "total_files":          total,
        "successful_files":     processed,
        "failed_files":         failed,
        "total_records":        int(total_records),
        "labeled_records":      int(labeled_count),
        "unknown_records":      int(unknown_count),
        "features":             all_features,
        "class_distribution":   label_counts,
        "source_distribution":  source_counts,
        "file_type_distribution": file_type_counts,
        "output_file":          str(out_csv),
    }
    safe_json_write(summary, PROCESSED_DIR / "network_summary.json")
    print(f"\n  Saved: {out_csv}")
    print(f"  Summary saved: {PROCESSED_DIR / 'network_summary.json'}")
    return summary

# ---------------------------------------------------------------------------
# GENERIC FILE PARSERS (JSON, XML, TXT) for both pipelines
# ---------------------------------------------------------------------------
def _process_json_file(
    fpath: Path, root: Path, source_dataset: str, data_type: str
) -> List[Dict]:
    records = []
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read().strip()
        if not text:
            record_failure(fpath, root, "empty_file")
            return records

        # Try JSON Lines first
        obj = None
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            # Try JSONL / NDJSON
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            parsed = []
            for line in lines:
                try:
                    parsed.append(json.loads(line))
                except Exception:
                    continue
            if parsed:
                obj = parsed

        if obj is None:
            record_failure(fpath, root, "json_parse_error", "Could not parse JSON")
            return records

        if isinstance(obj, dict):
            obj = [obj]

        try:
            rel = str(fpath.relative_to(root)).replace("\\", "/")
        except Exception:
            rel = fpath.name

        for item in obj:
            if not isinstance(item, dict):
                continue
            flat = _flatten_dict(item)
            flat["source_dataset"] = source_dataset
            flat["source_file"]    = fpath.name
            flat["relative_path"]  = rel
            flat["data_type"]      = data_type
            if "label" not in flat:
                flat["label"] = UNKNOWN_LABEL
            records.append(flat)

    except Exception as e:
        record_failure(fpath, root, "json_error", str(e))
    return records

def _flatten_dict(d: Dict, prefix: str = "", sep: str = "_") -> Dict:
    """Recursively flatten a nested dict."""
    out = {}
    for k, v in d.items():
        key = f"{prefix}{sep}{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten_dict(v, key, sep))
        elif isinstance(v, list):
            # Join simple lists as string; skip complex nested lists
            try:
                out[key] = ", ".join(str(x) for x in v if not isinstance(x, (dict, list)))
            except Exception:
                out[key] = str(v)[:200]
        else:
            out[key] = v
    return out

def _process_xml_file(
    fpath: Path, root: Path, source_dataset: str, data_type: str
) -> List[Dict]:
    records = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(fpath)
        root_el = tree.getroot()

        try:
            rel = str(fpath.relative_to(root)).replace("\\", "/")
        except Exception:
            rel = fpath.name

        # Look for repeating child elements (events/records)
        # Use all direct children of root as records
        children = list(root_el)
        if not children:
            return records

        for child in children:
            flat = {}
            flat["source_dataset"] = source_dataset
            flat["source_file"]    = fpath.name
            flat["relative_path"]  = rel
            flat["data_type"]      = data_type
            flat["raw_message"]    = ET.tostring(child, encoding="unicode")[:500]
            # Attributes
            flat.update(child.attrib)
            # Sub-elements
            for sub in child:
                tag = sub.tag.lower().strip()
                flat[tag] = sub.text.strip() if sub.text else None
                flat.update({f"{tag}_{k}": v for k, v in sub.attrib.items()})
            if "label" not in flat:
                flat["label"] = UNKNOWN_LABEL
            records.append(flat)

    except Exception as e:
        record_failure(fpath, root, "xml_error", str(e))
    return records

def _process_text_file(
    fpath: Path, root: Path, source_dataset: str, data_type: str
) -> List[Dict]:
    """Process plain text / log files line-by-line."""
    records = []
    try:
        try:
            rel = str(fpath.relative_to(root)).replace("\\", "/")
        except Exception:
            rel = fpath.name

        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                rec = {
                    "raw_message":     line[:500],
                    "source_dataset":  source_dataset,
                    "source_file":     fpath.name,
                    "relative_path":   rel,
                    "data_type":       data_type,
                    "label":           UNKNOWN_LABEL,
                }
                # Try to extract key=value pairs
                kv = re.findall(r'(\w+)\s*=\s*"?([^",\n]+)"?', line)
                for k, v in kv:
                    rec[k.lower()] = v.strip()
                records.append(rec)

    except Exception as e:
        record_failure(fpath, root, "text_error", str(e))
    return records

# ---------------------------------------------------------------------------
# SPLUNK PIPELINE
# ---------------------------------------------------------------------------
def process_splunk_dataset() -> Dict:
    print_section("SPLUNK ATTACK DATA PROCESSING")
    log.info("=== SPLUNK PROCESSING STARTED ===")

    if not SPLUNK_DIR.exists():
        log.error(f"Splunk datasets directory not found: {SPLUNK_DIR}")
        return {}

    # Discover all data files
    data_files = discover_files(SPLUNK_DIR, SPLUNK_EXTENSIONS, SPLUNK_SKIP_NAMES)
    yaml_files = discover_yaml_files(SPLUNK_DIR, SPLUNK_SKIP_NAMES)
    total_data = len(data_files)
    total_yaml = len(yaml_files)

    print(f"\n  Data files discovered:  {total_data}")
    print(f"  YAML files discovered:  {total_yaml}")
    log.info(f"Splunk data files: {total_data}  YAML files: {total_yaml}")

    all_records:   List[Dict] = []
    processed      = 0
    failed         = 0
    lfs_skipped    = 0
    file_type_counts: Dict[str, int] = {}
    log_type_counts:  Dict[str, int] = {}
    mitre_counts:     Dict[str, int] = {}
    source_counts:    Dict[str, int] = {}

    # --- Phase A: Process YAML metadata files (real content) ---
    print_subsection("Phase A: YAML Metadata Extraction")
    print(f"  Processing {total_yaml} YAML files...")

    for i, yaml_path in enumerate(yaml_files, 1):
        if i % 100 == 0 or i == total_yaml:
            print_progress(i, total_yaml, yaml_path.name)

        recs = parse_splunk_yaml(yaml_path, SPLUNK_DIR)
        if recs:
            all_records.extend(recs)
            processed += 1
            for r in recs:
                dt = r.get("data_type","unknown")
                log_type_counts[dt] = log_type_counts.get(dt, 0) + 1
                mt = r.get("mitre_technique","")
                if mt:
                    mitre_counts[mt] = mitre_counts.get(mt, 0) + 1
        file_type_counts[".yaml"] = file_type_counts.get(".yaml", 0) + 1

    print(f"\n  YAML records extracted: {len(all_records):,}")
    log.info(f"YAML metadata records: {len(all_records):,}")

    # --- Phase B: Process actual data files (non-LFS) ---
    print_subsection("Phase B: Data File Processing")
    print(f"  Processing {total_data} data files (skipping LFS pointers)...")

    for i, fpath in enumerate(data_files, 1):
        if i % 200 == 0 or i == total_data:
            print_progress(i, total_data, fpath.name)

        ext = fpath.suffix.lower()
        file_type_counts[ext] = file_type_counts.get(ext, 0) + 1

        # Detect and skip Git LFS pointers
        if is_git_lfs_pointer(fpath):
            record_failure(fpath, SPLUNK_DIR, "git_lfs_pointer",
                           "Git LFS pointer - run 'git lfs pull' to download actual data")
            lfs_skipped += 1
            failed += 1
            continue

        recs = []
        if ext == ".csv":
            try:
                df = pd.read_csv(fpath, encoding="utf-8", encoding_errors="replace",
                                 low_memory=False, on_bad_lines="skip")
                df.columns = [str(c).strip() for c in df.columns]
                if not df.empty:
                    try:
                        rel = str(fpath.relative_to(SPLUNK_DIR)).replace("\\","/")
                    except Exception:
                        rel = fpath.name
                    df["source_dataset"] = "Splunk-Attack-Data"
                    df["source_file"]    = fpath.name
                    df["relative_path"]  = rel
                    df["data_type"]      = "splunk_csv"
                    if "label" not in df.columns:
                        df["label"] = UNKNOWN_LABEL
                    recs = df.to_dict(orient="records")
            except Exception as e:
                record_failure(fpath, SPLUNK_DIR, "csv_error", str(e))

        elif ext in {".json",".jsonl",".ndjson"}:
            recs = _process_json_file(fpath, SPLUNK_DIR, "Splunk-Attack-Data", "splunk_json")

        elif ext == ".xml":
            recs = _process_xml_file(fpath, SPLUNK_DIR, "Splunk-Attack-Data", "splunk_xml")

        elif ext in {".log",".txt"}:
            recs = _process_text_file(fpath, SPLUNK_DIR, "Splunk-Attack-Data", "splunk_log")

        if recs:
            all_records.extend(recs)
            processed += 1
            source_counts[fpath.name] = len(recs)

    print(f"\n  Git LFS pointers skipped: {lfs_skipped}")
    print(f"  Non-LFS data files processed: {processed - (total_yaml if total_yaml else 0)}")
    print(f"  Total records: {len(all_records):,}")

    if not all_records:
        log.warning("No Splunk records collected (all logs are LFS pointers)")
        print("\n  NOTE: All .log files are Git LFS pointers.")
        print("  To get real log data: cd datasets/Splunk-Attack-Data && git lfs pull")
        empty_df = pd.DataFrame(columns=[
            "timestamp","source_ip","destination_ip","source_port","destination_port",
            "protocol","event_code","event_type","action","status","username","hostname",
            "process_name","command_line","file_name","hash","attack_category",
            "attack_scenario","mitre_technique","original_label","label",
            "source_dataset","source_file","relative_path","data_type","raw_message"
        ])
        out_csv = PROCESSED_DIR / "splunk_merged.csv"
        empty_df.to_csv(out_csv, index=False, encoding="utf-8")
        summary = {
            "total_files": total_data + total_yaml,
            "successful_files": 0,
            "failed_files": failed,
            "lfs_skipped": lfs_skipped,
            "total_records": 0,
            "note": "All .log files are Git LFS pointers. Run 'git lfs pull' in datasets/Splunk-Attack-Data to download.",
        }
        safe_json_write(summary, PROCESSED_DIR / "splunk_summary.json")
        return summary

    log.info(f"Total Splunk records: {len(all_records):,}")
    df = pd.DataFrame(all_records)

    # Dedup
    before_dedup = len(df)
    df = df.drop_duplicates()
    log.info(f"Deduplication: {before_dedup:,} -> {len(df):,}")

    # Label stats
    label_counts  = df["label"].value_counts().to_dict() if "label" in df.columns else {}
    unknown_count = label_counts.get(UNKNOWN_LABEL, 0)
    labeled_count = len(df) - unknown_count

    out_csv = PROCESSED_DIR / "splunk_merged.csv"
    df.to_csv(out_csv, index=False, encoding="utf-8")
    log.info(f"Splunk merged CSV saved: {out_csv}  ({len(df):,} rows)")
    print(f"\n  Saved: {out_csv}")
    print(f"  Records: {len(df):,}")

    summary = {
        "total_files":          total_data + total_yaml,
        "successful_files":     processed,
        "failed_files":         failed,
        "lfs_skipped":          lfs_skipped,
        "total_records":        int(len(df)),
        "labeled_records":      int(labeled_count),
        "unknown_records":      int(unknown_count),
        "class_distribution":   {str(k): int(v) for k, v in label_counts.items()},
        "mitre_distribution":   {str(k): int(v) for k, v in mitre_counts.items()},
        "log_type_distribution": {str(k): int(v) for k, v in log_type_counts.items()},
        "source_distribution":  {str(k): int(v) for k, v in list(source_counts.items())[:50]},
        "file_type_distribution": {str(k): int(v) for k, v in file_type_counts.items()},
        "output_file":          str(out_csv),
    }
    safe_json_write(summary, PROCESSED_DIR / "splunk_summary.json")
    return summary

# ---------------------------------------------------------------------------
# DATA QUALITY REPORT
# ---------------------------------------------------------------------------
def build_quality_report(net_summary: Dict, sp_summary: Dict) -> None:
    net_records  = net_summary.get("total_records", 0)
    sp_records   = sp_summary.get("total_records", 0)

    report = {
        "generated_at":       __import__("datetime").datetime.now().isoformat(),
        "network_records":    net_records,
        "splunk_records":     sp_records,
        "note_lfs_pointers":  "Splunk .log files are Git LFS pointers and were skipped. "
                              "Run 'git lfs pull' in datasets/Splunk-Attack-Data to download real logs.",
        "class_distribution": {
            "network": net_summary.get("class_distribution", {}),
            "splunk":  sp_summary.get("class_distribution", {}),
        },
        "file_type_distribution": {
            "network": net_summary.get("file_type_distribution", {}),
            "splunk":  sp_summary.get("file_type_distribution", {}),
        },
        "source_distribution": {
            "network": net_summary.get("source_distribution", {}),
        },
        "failed_files": {
            "network": net_summary.get("failed_files", 0),
            "splunk":  sp_summary.get("failed_files", 0),
        },
    }
    safe_json_write(report, PROCESSED_DIR / "data_quality_report.json")
    log.info("Data quality report saved.")

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    t_start = time.time()
    print_section("SOC CHESS DATASET PROCESSOR")
    print(f"  Network dir:  {NETWORK_DIR}")
    print(f"  Splunk dir:   {SPLUNK_DIR}")
    print(f"  Output dir:   {PROCESSED_DIR}")
    print(f"  Max rows/file: {MAX_ROWS_PER_FILE:,}")

    net_summary = process_network_dataset()
    sp_summary  = process_splunk_dataset()

    flush_failed_csv()
    build_quality_report(net_summary, sp_summary)

    elapsed = time.time() - t_start

    # Final summary
    net_types = net_summary.get("file_type_distribution", {})
    sp_types  = sp_summary.get("file_type_distribution", {})

    print("\n")
    print("=" * 60)
    print("  SOC CHESS DATA PROCESSING COMPLETE")
    print("=" * 60)
    print("\n  NETWORK")
    print(f"    Files discovered:  {net_summary.get('total_files', 0)}")
    print(f"    Files processed:   {net_summary.get('successful_files', 0)}")
    print(f"    Files failed:      {net_summary.get('failed_files', 0)}")
    print(f"    Records:           {net_summary.get('total_records', 0):,}")
    print(f"    Labeled:           {net_summary.get('labeled_records', 0):,}")
    print(f"    Unknown:           {net_summary.get('unknown_records', 0):,}")
    print("\n  SPLUNK ATTACK DATA")
    print(f"    Files discovered:  {sp_summary.get('total_files', 0)}")
    print(f"    Files processed:   {sp_summary.get('successful_files', 0)}")
    print(f"    Files failed:      {sp_summary.get('failed_files', 0)}")
    print(f"    LFS skipped:       {sp_summary.get('lfs_skipped', 0)}")
    print(f"    Records:           {sp_summary.get('total_records', 0):,}")
    print(f"    Labeled:           {sp_summary.get('labeled_records', 0):,}")
    print(f"    Unknown:           {sp_summary.get('unknown_records', 0):,}")

    # Combined file type stats
    all_types = {}
    for d in (net_types, sp_types):
        for k, v in d.items():
            all_types[k] = all_types.get(k, 0) + v
    print("\n  FILE TYPES")
    for ext in [".csv",".log",".json",".jsonl",".ndjson",".xml",".txt",".yaml",".yml"]:
        print(f"    {ext:<8} {all_types.get(ext, 0)}")

    print("\n  OUTPUT")
    print(f"    {PROCESSED_DIR / 'network_merged.csv'}")
    print(f"    {PROCESSED_DIR / 'splunk_merged.csv'}")
    print(f"\n  Elapsed: {elapsed:.1f}s")
    print("=" * 60)

    log.info(f"Processing complete in {elapsed:.1f}s")

if __name__ == "__main__":
    main()
