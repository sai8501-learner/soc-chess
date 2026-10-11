import os
import re
import sys
import json
import time
import socket
import logging
import asyncio
import subprocess
import threading
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from backend.config import settings
from backend.database import execute, query, query_one
from backend.spark_engine.spark_processor import spark_processor
from backend.ml_engine.mlp_pipeline import mlp_pipeline
from backend.ml_engine.risk_engine import risk_engine
from backend.services.threat_intel import threat_intel_service
from backend.services.llm_analyst import llm_analyst
from backend.services.auth_service import AuthError, auth_service

router = APIRouter(prefix="/api/network", tags=["Network & TShark"])
logger = logging.getLogger("socchess.network")

# Network Capture Runtime State
class CaptureState:
    process: Optional[subprocess.Popen] = None
    interface: str = settings.DEFAULT_INTERFACE
    is_capturing: bool = False
    packet_count: int = 0
    start_time: Optional[float] = None
    session_id: Optional[str] = None
    lock: threading.Lock = threading.Lock()
    active_websockets: List[WebSocket] = []

capture_state = CaptureState()

# Pydantic Request Models
class StartCaptureRequest(BaseModel):
    interface: str = Field(default="Ethernet 7", description="Selected network interface")
    packet_limit: Optional[int] = Field(default=1000, ge=1, le=50000, description="Packet limit")
    safe_filter: Optional[str] = Field(default="", max_length=100, description="Safe BPF or display filter")

# ═══════════════════════════════════════════════════════════════
# 1. INTERFACE DISCOVERY (Real TShark)
# ═══════════════════════════════════════════════════════════════
@router.get("/interfaces")
def get_interfaces():
    """Detects available network interfaces using the actual host TShark."""
    tshark_path = settings.TSHARK_PATH
    if not os.path.exists(tshark_path):
        return {
            "tshark_available": False,
            "tshark_path": tshark_path,
            "interfaces": [
                {
                    "id": "1",
                    "name": "Cloud / Simulated Interface (TShark Offline)",
                    "raw_device": "eth0",
                    "description": "Cloud deployment mode — live packet sniffing disabled (TShark not installed on host)"
                }
            ],
            "current_interface": "Cloud / Simulated Interface (TShark Offline)"
        }

    interfaces = []
    try:
        startupinfo = None
        creationflags = 0
        if sys.platform == 'win32':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW

        proc = subprocess.run(
            [tshark_path, "-D"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=12,
            startupinfo=startupinfo,
            creationflags=creationflags
        )

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.match(r"^(\d+)\.\s+(.*?)(?:\s+\((.*?)\))?$", line)
            if match:
                idx, raw_name, friendly = match.groups()
                interfaces.append({
                    "id": idx,
                    "name": friendly if friendly else raw_name,
                    "raw_device": raw_name,
                    "description": f"Host Interface {idx}: {friendly or raw_name}"
                })
            else:
                interfaces.append({
                    "id": str(len(interfaces) + 1),
                    "name": line,
                    "raw_device": line,
                    "description": line
                })

    except Exception as e:
        logger.warning(f"[!] TShark -D slow or error ({e}). Using standard host adapter defaults.")
        interfaces = [
            {"id": "1", "name": "Ethernet 7", "raw_device": "\\Device\\NPF_{Ethernet7}", "description": "VirtualBox Host-Only Adapter (Ethernet 7)"},
            {"id": "2", "name": "Ethernet", "raw_device": "\\Device\\NPF_{Ethernet}", "description": "Host Ethernet Adapter"},
            {"id": "3", "name": "Wi-Fi", "raw_device": "\\Device\\NPF_{WiFi}", "description": "Host Wireless Adapter"}
        ]

    return {
        "tshark_available": True,
        "tshark_path": tshark_path,
        "interfaces": interfaces,
        "current_interface": capture_state.interface
    }

# ═══════════════════════════════════════════════════════════════
# 2. CAPTURE CONTROLS (Real TShark Process)
# ═══════════════════════════════════════════════════════════════
@router.post("/capture/start")
async def start_capture(req: StartCaptureRequest):
    """Starts a real controlled TShark capture on the host."""
    with capture_state.lock:
        if capture_state.is_capturing:
            return {
                "status": "already_running",
                "message": f"Capture is already active on interface '{capture_state.interface}'",
                "session_id": capture_state.session_id
            }

        tshark_path = settings.TSHARK_PATH
        if not os.path.exists(tshark_path):
            raise HTTPException(status_code=404, detail="TShark executable not found")

        clean_iface = re.sub(r'[^a-zA-Z0-9\s_\-\.\{\}\\\(\)]', '', req.interface).strip()
        if not clean_iface:
            clean_iface = settings.DEFAULT_INTERFACE

        session_id = f"sess_{int(time.time())}"
        capture_state.interface = clean_iface
        capture_state.is_capturing = True
        capture_state.packet_count = 0
        capture_state.start_time = time.time()
        capture_state.session_id = session_id

        # Insert network session in DB
        try:
            execute(
                "INSERT INTO network_sessions (session_id, interface, status) VALUES (%s, %s, %s)",
                (session_id, clean_iface, "ACTIVE")
            )
        except Exception:
            pass

        # Spawn background capture thread
        threading.Thread(
            target=run_tshark_process,
            args=(tshark_path, clean_iface, session_id, req.packet_limit),
            daemon=True,
            name=f"TSharkCapture_{session_id}"
        ).start()

        return {
            "status": "started",
            "interface": clean_iface,
            "session_id": session_id,
            "packet_limit": req.packet_limit
        }

@router.post("/capture/stop")
def stop_capture():
    """Safely terminates the active TShark capture process."""
    with capture_state.lock:
        if not capture_state.is_capturing:
            return {"status": "not_running", "message": "No capture is currently active"}

        if capture_state.process:
            try:
                capture_state.process.terminate()
                capture_state.process.wait(timeout=2)
            except Exception:
                try:
                    capture_state.process.kill()
                except Exception:
                    pass
            capture_state.process = None

        capture_state.is_capturing = False
        duration = time.time() - (capture_state.start_time or time.time())

        # Update session in DB
        try:
            execute(
                "UPDATE network_sessions SET status='STOPPED', end_time=NOW(), packet_count=%s WHERE session_id=%s",
                (capture_state.packet_count, capture_state.session_id)
            )
        except Exception:
            pass

        return {
            "status": "stopped",
            "session_id": capture_state.session_id,
            "packets_captured": capture_state.packet_count,
            "duration_seconds": round(duration, 2)
        }

@router.get("/capture/status")
def get_capture_status():
    """Returns the true status and throughput metrics of the packet capture engine."""
    duration = (time.time() - capture_state.start_time) if (capture_state.is_capturing and capture_state.start_time) else 0
    pps = round(capture_state.packet_count / duration, 1) if duration > 0 else 0

    return {
        "is_capturing": capture_state.is_capturing,
        "interface": capture_state.interface,
        "session_id": capture_state.session_id,
        "packet_count": capture_state.packet_count,
        "packets_per_second": pps,
        "duration_seconds": round(duration, 1),
        "tshark_available": os.path.exists(settings.TSHARK_PATH),
        "wireshark_available": os.path.exists(settings.WIRESHARK_PATH)
    }

@router.get("/packets")
def get_packets(limit: int = 100, offset: int = 0):
    """Retrieves real captured network packet metadata from MySQL."""
    try:
        rows = query(
            "SELECT * FROM network_events ORDER BY id DESC LIMIT %s OFFSET %s",
            (min(limit, 500), offset)
        )
        total = query_one("SELECT COUNT(*) as count FROM network_events")
        return {
            "total": total["count"] if total else len(rows),
            "data": rows
        }
    except Exception as e:
        logger.warning(f"[!] Error fetching network packets: {e}")
        return {
            "total": 0,
            "data": []
        }

# ═══════════════════════════════════════════════════════════════
# 3. OPEN ACTUAL WIRESHARK GUI
# ═══════════════════════════════════════════════════════════════
@router.post("/open-wireshark")
def open_wireshark():
    """Securely launches the real host Wireshark application GUI."""
    wireshark_path = settings.WIRESHARK_PATH
    if not os.path.exists(wireshark_path):
        raise HTTPException(
            status_code=404,
            detail=f"Wireshark GUI not found at {wireshark_path}. Please verify installation."
        )

    try:
        subprocess.Popen([wireshark_path, "-i", capture_state.interface])
        return {
            "status": "launched",
            "executable": wireshark_path,
            "interface": capture_state.interface
        }
    except Exception as e:
        logger.error(f"[!] Error launching Wireshark: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to launch Wireshark: {str(e)}")

# ═══════════════════════════════════════════════════════════════
# 4. WEBSOCKET REAL-TIME STREAM
# ═══════════════════════════════════════════════════════════════
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if settings.AUTH_ENABLED:
        token = websocket.query_params.get("token", "")
        try:
            auth_service.get_authenticated_user(token)
        except Exception:
            await websocket.close(code=1008)
            return
    await websocket.accept()
    capture_state.active_websockets.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        if websocket in capture_state.active_websockets:
            capture_state.active_websockets.remove(websocket)

def broadcast_packet(packet_dict: Dict[str, Any]):
    """Broadcasts parsed packet to all active React WebSocket clients."""
    if not capture_state.active_websockets:
        return
    msg = json.dumps({"type": "new_packet", "data": packet_dict})
    loop = None
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        pass

    for ws in list(capture_state.active_websockets):
        try:
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(ws.send_text(msg), loop)
        except Exception:
            pass

# ═══════════════════════════════════════════════════════════════
# 5. TSHARK SUBPROCESS ENGINE WITH SPARK + MLP + RISK ENGINE
# ═══════════════════════════════════════════════════════════════
def run_tshark_process(tshark_path: str, interface: str, session_id: str, limit: int):
    """Subprocess loop that parses live TShark output and streams through Spark + MLP + Risk Engine."""
    cmd = [tshark_path, "-i", interface, "-T", "json", "-l", "-n"]
    startupinfo = None
    creationflags = 0
    if sys.platform == 'win32':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            startupinfo=startupinfo,
            creationflags=creationflags
        )
        capture_state.process = proc
        logger.info(f"[*] TShark capture active (PID: {proc.pid}) on interface '{interface}'")

        json_buf = ""
        for line in proc.stdout:
            if not capture_state.is_capturing:
                break

            line_str = line.strip()
            if not line_str or line_str in ["[", "]"]:
                continue

            json_buf += line
            if line_str.endswith("}") or line_str.endswith("},"):
                raw_json = json_buf.rstrip(",\n\r ")
                json_buf = ""
                try:
                    p_obj = json.loads(raw_json)
                    layers = p_obj.get("_source", {}).get("layers", {})
                    if not layers:
                        continue

                    ip = layers.get("ip", {})
                    tcp = layers.get("tcp", {})
                    udp = layers.get("udp", {})
                    frame = layers.get("frame", {})

                    src_ip = ip.get("ip.src", "192.168.56.104")
                    dst_ip = ip.get("ip.dst", "192.168.56.107")
                    proto = "TCP" if tcp else ("UDP" if udp else "IP")
                    src_port = int(tcp.get("tcp.srcport", udp.get("udp.srcport", 0))) or None
                    dst_port = int(tcp.get("tcp.dstport", udp.get("udp.dstport", 0))) or None
                    flags = tcp.get("tcp.flags_tree", {}).get("tcp.flags.str", "") if tcp else ""
                    pkt_len = int(frame.get("frame.len", ip.get("ip.len", 64)))

                    # 1. Spark Feature Extraction
                    raw_pkt = {
                        "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port or 50000,
                        "dst_port": dst_port or 80, "protocol": proto, "length": pkt_len, "flags": flags
                    }
                    _, feat_vector = spark_processor.process_single_packet(raw_pkt)

                    # 2. MLP Neural Network Inference
                    pred = mlp_pipeline.predict(feat_vector)
                    attack_type = pred["attack_type"]
                    conf = pred["confidence"]
                    is_attack = pred["is_attack"]

                    # 3. Threat Intel Enrichment
                    ti_res = threat_intel_service.lookup_ip(src_ip)
                    ti_score = float(ti_res.get("threat_score", 0))

                    # 4. Risk Score Engine
                    risk_res = risk_engine.calculate_risk(
                        attack_type=attack_type,
                        mlp_confidence=conf,
                        is_attack=is_attack,
                        threat_intel_score=ti_score,
                        destination_ip=dst_ip
                    )
                    risk_val = risk_res["risk_score"]
                    risk_stat = risk_res["risk_status"]

                    capture_state.packet_count += 1
                    packet_data = {
                        "packet_no": capture_state.packet_count,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "session_id": session_id,
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "source_port": src_port,
                        "destination_port": dst_port,
                        "protocol": proto,
                        "packet_length": pkt_len,
                        "tcp_flags": flags,
                        "interface": interface,
                        "classification": risk_stat if is_attack else "NORMAL",
                        "confidence": conf,
                        "mlp_confidence": conf,
                        "attack_type": attack_type,
                        "risk_score": risk_val,
                        "risk_status": risk_stat
                    }

                    # Persist event in DB
                    try:
                        execute("""
                            INSERT INTO network_events (session_id, packet_no, source_ip, destination_ip, source_port, destination_port, protocol, packet_length, tcp_flags, interface, classification, confidence, risk_score)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (session_id, packet_data["packet_no"], src_ip, dst_ip, src_port, dst_port, proto, pkt_len, flags, interface, packet_data["classification"], conf, risk_val))

                        # If attack with high risk, auto-generate AI alert
                        if is_attack and risk_val >= 50:
                            execute("""
                                INSERT INTO ai_alerts (source_ip, destination_ip, source_port, destination_port, protocol, attack_type, confidence, mlp_confidence, risk_score, risk_status, severity, source, status, recommended_action, evidence, threat_intel, llm_explanation)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """, (
                                src_ip, dst_ip, src_port, dst_port, proto, attack_type, conf, conf, risk_val, risk_stat, risk_stat,
                                "NETWORK", "open", "Apply firewall rule and isolate source IP",
                                json.dumps(risk_res["evidence"]), json.dumps(ti_res),
                                f"Live TShark packet classified as {attack_type} by 3-Hidden-Layer MLP ({conf:.1f}% conf). Risk: {risk_val}/100 ({risk_stat})."
                            ))
                    except Exception:
                        pass

                    broadcast_packet(packet_data)

                    if limit and capture_state.packet_count >= limit:
                        break

                except json.JSONDecodeError:
                    continue

    except Exception as e:
        logger.error(f"[!] Error in TShark process loop: {e}")
    finally:
        with capture_state.lock:
            capture_state.is_capturing = False
            if capture_state.process:
                try:
                    capture_state.process.terminate()
                except Exception:
                    pass
                capture_state.process = None
