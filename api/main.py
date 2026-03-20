from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
from pathlib import Path
from typing import Optional
from collections import defaultdict, deque
from datetime import datetime, timezone
import asyncio
import threading
import socket

from scapy.all import sniff, IP, TCP, UDP

try:
    import psutil
except ImportError:
    psutil = None

class AlertTraceInput(BaseModel):
    source_ip: str
    destination_ip: str
    attack_type: Optional[str] = None


class LiveCaptureResponse(BaseModel):
    status: str
    message: str

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained model
model = joblib.load("model/intrusion_model.pkl")
ALERTS_FILE = Path("data/intrusion_alerts.csv")
PROFILES_FILE = Path("data/attacker_profiles.csv")
ALERT_COLUMNS = [
    "timestamp",
    "attack_type",
    "confidence",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packets_in_flow",
    "bytes_in_flow",
    "top_trigger_features",
]
BENIGN_LABELS = {
    "benign",
    "normal",
    "normal traffic",
    "0",
    "none",
}

connected_clients: set[WebSocket] = set()
live_alerts = deque(maxlen=300)
alerts_lock = threading.Lock()
alert_queue: asyncio.Queue = asyncio.Queue()
main_loop: Optional[asyncio.AbstractEventLoop] = None
broadcast_task: Optional[asyncio.Task] = None

live_status = {
    "running": False,
    "packets_seen": 0,
    "flows_seen": 0,
    "last_error": None,
    "started_at": None,
}


def get_wired_connection_status() -> dict:
    if psutil is None:
        return {
            "connected": False,
            "interfaces": [],
            "reason": "psutil not installed",
        }

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    wired_keywords = (
        "ethernet",
        "eth",
        "lan",
        "wired",
        "local area connection",
    )

    active_wired = []

    for interface_name, interface_stats in stats.items():
        name_lower = interface_name.lower()
        if not any(keyword in name_lower for keyword in wired_keywords):
            continue

        if not interface_stats.isup:
            continue

        iface_addrs = addrs.get(interface_name, [])
        has_ipv4 = any(
            addr.family == socket.AF_INET and not str(addr.address).startswith("127.")
            for addr in iface_addrs
        )

        if not has_ipv4:
            continue

        active_wired.append(interface_name)

    return {
        "connected": len(active_wired) > 0,
        "interfaces": active_wired,
        "reason": "wired interface active" if active_wired else "no active wired interface",
    }


def persist_alert(alert: dict) -> None:
    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    normalized_alert = {
        "timestamp": alert.get("timestamp"),
        "attack_type": alert.get("attack_type"),
        "confidence": alert.get("confidence", 0),
        "source_ip": alert.get("source_ip"),
        "destination_ip": alert.get("destination_ip"),
        "source_port": alert.get("source_port", 0),
        "destination_port": alert.get("destination_port", 0),
        "protocol": alert.get("protocol", ""),
        "packets_in_flow": alert.get("packets_in_flow", 0),
        "bytes_in_flow": alert.get("bytes_in_flow", 0),
        "top_trigger_features": alert.get("top_trigger_features", ""),
    }
    alert_df = pd.DataFrame([normalized_alert], columns=ALERT_COLUMNS)

    if ALERTS_FILE.exists() and ALERTS_FILE.stat().st_size > 0:
        alert_df.to_csv(ALERTS_FILE, mode="a", index=False, header=False)
    else:
        alert_df.to_csv(ALERTS_FILE, mode="w", index=False, header=True)


def enqueue_alert_threadsafe(alert: dict) -> None:
    if main_loop is None:
        return
    main_loop.call_soon_threadsafe(alert_queue.put_nowait, alert)


def is_attack_prediction(prediction: object) -> bool:
    pred = str(prediction).strip().lower()
    return pred not in BENIGN_LABELS


def extract_top_trigger_features(feature_df: pd.DataFrame, top_n: int = 3) -> list[str]:
    if feature_df.empty:
        return []

    if not hasattr(model, "feature_importances_"):
        return []

    importance_values = list(model.feature_importances_)
    feature_names = list(feature_df.columns)
    feature_values = feature_df.iloc[0].to_dict()

    feature_scores = []
    for feature_name, importance in zip(feature_names, importance_values):
        value = float(feature_values.get(feature_name, 0))
        score = abs(value) * float(importance)
        feature_scores.append((feature_name, score))

    feature_scores.sort(key=lambda item: item[1], reverse=True)
    return [name for name, _ in feature_scores[:top_n]]


def load_alerts_dataframe(include_benign: bool = False) -> pd.DataFrame:
    if not ALERTS_FILE.exists():
        return pd.DataFrame(columns=ALERT_COLUMNS)

    data = pd.read_csv(ALERTS_FILE)
    if data.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    for col in ALERT_COLUMNS:
        if col not in data.columns:
            data[col] = ""

    data["source_ip"] = data["source_ip"].astype(str).str.strip()
    data["destination_ip"] = data["destination_ip"].astype(str).str.strip()
    data["attack_type"] = data["attack_type"].astype(str).str.strip()

    valid_ips = data["source_ip"].str.contains(r"\.", na=False) & data[
        "destination_ip"
    ].str.contains(r"\.", na=False)
    data = data[valid_ips]

    data["confidence"] = pd.to_numeric(data["confidence"], errors="coerce").fillna(0)
    data["packets_in_flow"] = pd.to_numeric(data["packets_in_flow"], errors="coerce").fillna(0)
    data["bytes_in_flow"] = pd.to_numeric(data["bytes_in_flow"], errors="coerce").fillna(0)

    if not include_benign:
        data = data[~data["attack_type"].str.lower().isin(BENIGN_LABELS)]

    return data[ALERT_COLUMNS]


def build_attacker_profiles(data: pd.DataFrame) -> pd.DataFrame:
    if data.empty:
        return pd.DataFrame(
            columns=[
                "source_ip",
                "total_alerts",
                "targets_hit",
                "targets",
                "attack_types",
                "average_confidence",
                "campaign_severity",
                "last_seen",
            ]
        )

    profiles = defaultdict(
        lambda: {
            "total_alerts": 0,
            "targets": set(),
            "attack_types": set(),
            "total_confidence": 0.0,
            "last_seen": None,
        }
    )

    for _, row in data.iterrows():
        source_ip = str(row["source_ip"])
        destination_ip = str(row["destination_ip"])
        attack_type = str(row["attack_type"])
        confidence = float(row["confidence"])
        timestamp = row["timestamp"]

        profiles[source_ip]["total_alerts"] += 1
        profiles[source_ip]["targets"].add(destination_ip)
        profiles[source_ip]["attack_types"].add(attack_type)
        profiles[source_ip]["total_confidence"] += confidence
        profiles[source_ip]["last_seen"] = timestamp

    rows = []
    for source_ip, info in profiles.items():
        total_alerts = info["total_alerts"]
        targets_hit = len(info["targets"])
        average_confidence = (
            info["total_confidence"] / total_alerts if total_alerts > 0 else 0.0
        )

        if total_alerts >= 10 or targets_hit >= 5 or average_confidence >= 95:
            severity = "HIGH"
        elif total_alerts >= 5 or targets_hit >= 3 or average_confidence >= 90:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        rows.append(
            {
                "source_ip": source_ip,
                "total_alerts": total_alerts,
                "targets_hit": targets_hit,
                "targets": ", ".join(sorted(info["targets"])),
                "attack_types": ", ".join(sorted(info["attack_types"])),
                "average_confidence": round(average_confidence, 2),
                "campaign_severity": severity,
                "last_seen": info["last_seen"],
            }
        )

    profile_df = pd.DataFrame(rows)
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    profile_df["severity_rank"] = profile_df["campaign_severity"].map(severity_rank)
    profile_df = profile_df.sort_values(
        by=["severity_rank", "total_alerts"], ascending=[True, False]
    ).drop(columns=["severity_rank"])

    return profile_df


class LivePacketDetector:
    def __init__(self):
        self.stop_event = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None
        self.flows = defaultdict(
            lambda: {
                "start_time": None,
                "end_time": None,
                "packet_lengths": [],
                "total_fwd_packets": 0,
                "total_fwd_bytes": 0,
            }
        )

    def build_feature_row(self, flow_key, flow_data):
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key

        start_time = flow_data["start_time"]
        end_time = flow_data["end_time"]
        duration = max((end_time - start_time).total_seconds() * 1_000_000, 1)

        total_fwd_packets = flow_data["total_fwd_packets"]
        total_fwd_bytes = flow_data["total_fwd_bytes"]
        packet_lengths = flow_data["packet_lengths"]

        max_len = max(packet_lengths) if packet_lengths else 0
        min_len = min(packet_lengths) if packet_lengths else 0
        mean_len = sum(packet_lengths) / len(packet_lengths) if packet_lengths else 0

        flow_bytes_s = total_fwd_bytes / (duration / 1_000_000)
        flow_packets_s = total_fwd_packets / (duration / 1_000_000)

        row = {
            "Destination Port": dst_port,
            "Flow Duration": duration,
            "Total Fwd Packets": total_fwd_packets,
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Fwd Packet Length Max": max_len,
            "Fwd Packet Length Min": min_len,
            "Fwd Packet Length Mean": mean_len,
            "Fwd Packet Length Std": 0,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0,
            "Bwd Packet Length Std": 0,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_packets_s,
            "Flow IAT Mean": 0,
            "Flow IAT Std": 0,
            "Flow IAT Max": 0,
            "Flow IAT Min": 0,
            "Fwd IAT Total": 0,
            "Fwd IAT Mean": 0,
            "Fwd IAT Std": 0,
            "Fwd IAT Max": 0,
            "Fwd IAT Min": 0,
            "Bwd IAT Total": 0,
            "Bwd IAT Mean": 0,
            "Bwd IAT Std": 0,
            "Bwd IAT Max": 0,
            "Bwd IAT Min": 0,
            "Fwd Header Length": 0,
            "Bwd Header Length": 0,
            "Fwd Packets/s": flow_packets_s,
            "Bwd Packets/s": 0,
            "Min Packet Length": min_len,
            "Max Packet Length": max_len,
            "Packet Length Mean": mean_len,
            "Packet Length Std": 0,
            "Packet Length Variance": 0,
            "FIN Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "Average Packet Size": mean_len,
            "Subflow Fwd Bytes": total_fwd_bytes,
            "Init_Win_bytes_forward": 0,
            "Init_Win_bytes_backward": 0,
            "act_data_pkt_fwd": total_fwd_packets,
            "min_seg_size_forward": 0,
            "Active Mean": 0,
            "Active Max": 0,
            "Active Min": 0,
            "Idle Mean": 0,
            "Idle Max": 0,
            "Idle Min": 0,
        }

        return pd.DataFrame([row]), {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packets_in_flow": total_fwd_packets,
            "bytes_in_flow": total_fwd_bytes,
        }

    def handle_packet(self, packet):
        if IP not in packet:
            return

        live_status["packets_seen"] += 1

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_name = "IP"
        src_port = 0
        dst_port = 0

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto_name = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto_name = "UDP"

        flow_key = (src_ip, dst_ip, src_port, dst_port, proto_name)
        now = datetime.now(timezone.utc)
        pkt_len = len(packet)

        flow = self.flows[flow_key]
        if flow["start_time"] is None:
            flow["start_time"] = now
            live_status["flows_seen"] += 1

        flow["end_time"] = now
        flow["packet_lengths"].append(pkt_len)
        flow["total_fwd_packets"] += 1
        flow["total_fwd_bytes"] += pkt_len

        if flow["total_fwd_packets"] < 5:
            return

        features_df, trace_info = self.build_feature_row(flow_key, flow)

        prediction = model.predict(features_df)[0]
        if hasattr(model, "predict_proba"):
            confidence = float(max(model.predict_proba(features_df)[0])) * 100
        else:
            confidence = 100.0

        if not is_attack_prediction(prediction):
            return

        top_features = extract_top_trigger_features(features_df, top_n=3)

        alert = {
            "timestamp": now.isoformat(),
            "source_ip": trace_info["source_ip"],
            "destination_ip": trace_info["destination_ip"],
            "source_port": trace_info["source_port"],
            "destination_port": trace_info["destination_port"],
            "protocol": trace_info["protocol"],
            "attack_type": str(prediction),
            "confidence": round(confidence, 2),
            "packets_in_flow": trace_info["packets_in_flow"],
            "bytes_in_flow": trace_info["bytes_in_flow"],
            "top_trigger_features": "|".join(top_features),
        }

        enqueue_alert_threadsafe(alert)

    def run_capture(self):
        while not self.stop_event.is_set():
            try:
                sniff(prn=self.handle_packet, store=False, timeout=1)
            except Exception as exc:
                live_status["last_error"] = str(exc)
                self.stop_event.set()

        live_status["running"] = False

    def start(self):
        if self.capture_thread and self.capture_thread.is_alive():
            return

        self.stop_event.clear()
        live_status["last_error"] = None
        live_status["running"] = True
        live_status["started_at"] = datetime.now(timezone.utc).isoformat()
        self.capture_thread = threading.Thread(target=self.run_capture, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.stop_event.set()
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        live_status["running"] = False


live_detector = LivePacketDetector()


async def broadcast_alerts():
    while True:
        alert = await alert_queue.get()

        with alerts_lock:
            live_alerts.appendleft(alert)
        persist_alert(alert)

        disconnected = []
        for client in connected_clients:
            try:
                await client.send_json({"type": "alert", "data": alert})
            except Exception:
                disconnected.append(client)

        for client in disconnected:
            connected_clients.discard(client)


class TrafficInput(BaseModel):
    Destination_Port: float
    Flow_Duration: float
    Total_Fwd_Packets: float
    Total_Length_of_Fwd_Packets: float
    Fwd_Packet_Length_Max: float
    Fwd_Packet_Length_Min: float
    Fwd_Packet_Length_Mean: float
    Fwd_Packet_Length_Std: float
    Bwd_Packet_Length_Max: float
    Bwd_Packet_Length_Min: float
    Bwd_Packet_Length_Mean: float
    Bwd_Packet_Length_Std: float
    Flow_Bytes_s: float
    Flow_Packets_s: float
    Flow_IAT_Mean: float
    Flow_IAT_Std: float
    Flow_IAT_Max: float
    Flow_IAT_Min: float
    Fwd_IAT_Total: float
    Fwd_IAT_Mean: float
    Fwd_IAT_Std: float
    Fwd_IAT_Max: float
    Fwd_IAT_Min: float
    Bwd_IAT_Total: float
    Bwd_IAT_Mean: float
    Bwd_IAT_Std: float
    Bwd_IAT_Max: float
    Bwd_IAT_Min: float
    Fwd_Header_Length: float
    Bwd_Header_Length: float
    Fwd_Packets_s: float
    Bwd_Packets_s: float
    Min_Packet_Length: float
    Max_Packet_Length: float
    Packet_Length_Mean: float
    Packet_Length_Std: float
    Packet_Length_Variance: float
    FIN_Flag_Count: float
    PSH_Flag_Count: float
    ACK_Flag_Count: float
    Average_Packet_Size: float
    Subflow_Fwd_Bytes: float
    Init_Win_bytes_forward: float
    Init_Win_bytes_backward: float
    act_data_pkt_fwd: float
    min_seg_size_forward: float
    Active_Mean: float
    Active_Max: float
    Active_Min: float
    Idle_Mean: float
    Idle_Max: float
    Idle_Min: float


@app.get("/")
def home():
    return {"message": "Network Intrusion Detection API running"}


@app.on_event("startup")
async def startup_event():
    global main_loop, broadcast_task
    main_loop = asyncio.get_running_loop()
    broadcast_task = asyncio.create_task(broadcast_alerts())

    try:
        live_detector.start()
    except Exception as exc:
        live_status["last_error"] = str(exc)
        live_status["running"] = False


@app.on_event("shutdown")
async def shutdown_event():
    global broadcast_task
    live_detector.stop()

    if broadcast_task:
        broadcast_task.cancel()


@app.post("/predict")
def predict_attack(traffic: TrafficInput):
    input_data = pd.DataFrame([{
        "Destination Port": traffic.Destination_Port,
        "Flow Duration": traffic.Flow_Duration,
        "Total Fwd Packets": traffic.Total_Fwd_Packets,
        "Total Length of Fwd Packets": traffic.Total_Length_of_Fwd_Packets,
        "Fwd Packet Length Max": traffic.Fwd_Packet_Length_Max,
        "Fwd Packet Length Min": traffic.Fwd_Packet_Length_Min,
        "Fwd Packet Length Mean": traffic.Fwd_Packet_Length_Mean,
        "Fwd Packet Length Std": traffic.Fwd_Packet_Length_Std,
        "Bwd Packet Length Max": traffic.Bwd_Packet_Length_Max,
        "Bwd Packet Length Min": traffic.Bwd_Packet_Length_Min,
        "Bwd Packet Length Mean": traffic.Bwd_Packet_Length_Mean,
        "Bwd Packet Length Std": traffic.Bwd_Packet_Length_Std,
        "Flow Bytes/s": traffic.Flow_Bytes_s,
        "Flow Packets/s": traffic.Flow_Packets_s,
        "Flow IAT Mean": traffic.Flow_IAT_Mean,
        "Flow IAT Std": traffic.Flow_IAT_Std,
        "Flow IAT Max": traffic.Flow_IAT_Max,
        "Flow IAT Min": traffic.Flow_IAT_Min,
        "Fwd IAT Total": traffic.Fwd_IAT_Total,
        "Fwd IAT Mean": traffic.Fwd_IAT_Mean,
        "Fwd IAT Std": traffic.Fwd_IAT_Std,
        "Fwd IAT Max": traffic.Fwd_IAT_Max,
        "Fwd IAT Min": traffic.Fwd_IAT_Min,
        "Bwd IAT Total": traffic.Bwd_IAT_Total,
        "Bwd IAT Mean": traffic.Bwd_IAT_Mean,
        "Bwd IAT Std": traffic.Bwd_IAT_Std,
        "Bwd IAT Max": traffic.Bwd_IAT_Max,
        "Bwd IAT Min": traffic.Bwd_IAT_Min,
        "Fwd Header Length": traffic.Fwd_Header_Length,
        "Bwd Header Length": traffic.Bwd_Header_Length,
        "Fwd Packets/s": traffic.Fwd_Packets_s,
        "Bwd Packets/s": traffic.Bwd_Packets_s,
        "Min Packet Length": traffic.Min_Packet_Length,
        "Max Packet Length": traffic.Max_Packet_Length,
        "Packet Length Mean": traffic.Packet_Length_Mean,
        "Packet Length Std": traffic.Packet_Length_Std,
        "Packet Length Variance": traffic.Packet_Length_Variance,
        "FIN Flag Count": traffic.FIN_Flag_Count,
        "PSH Flag Count": traffic.PSH_Flag_Count,
        "ACK Flag Count": traffic.ACK_Flag_Count,
        "Average Packet Size": traffic.Average_Packet_Size,
        "Subflow Fwd Bytes": traffic.Subflow_Fwd_Bytes,
        "Init_Win_bytes_forward": traffic.Init_Win_bytes_forward,
        "Init_Win_bytes_backward": traffic.Init_Win_bytes_backward,
        "act_data_pkt_fwd": traffic.act_data_pkt_fwd,
        "min_seg_size_forward": traffic.min_seg_size_forward,
        "Active Mean": traffic.Active_Mean,
        "Active Max": traffic.Active_Max,
        "Active Min": traffic.Active_Min,
        "Idle Mean": traffic.Idle_Mean,
        "Idle Max": traffic.Idle_Max,
        "Idle Min": traffic.Idle_Min
    }])

    prediction = model.predict(input_data)[0]

    probabilities = model.predict_proba(input_data)[0]
    confidence = float(max(probabilities)) * 100

    feature_importances = model.feature_importances_
    feature_names = input_data.columns

    feature_scores = []
    for feature_name, importance in zip(feature_names, feature_importances):
        value = input_data.iloc[0][feature_name]
        score = abs(value) * importance
        feature_scores.append((feature_name, float(value), float(importance), float(score)))

    feature_scores.sort(key=lambda x: x[3], reverse=True)
    top_features = [item[0] for item in feature_scores[:5]]

    return {
        "predicted_attack": prediction,
        "confidence": round(confidence, 2),
        "top_features": top_features
    }

@app.get("/alerts")
def get_alerts():
    data = load_alerts_dataframe(include_benign=False)
    if data.empty:
        return {"message": "No intrusion alerts found yet.", "alerts": []}

    return {"alerts": data.to_dict(orient="records")}


@app.get("/live/alerts")
def get_live_alerts():
    with alerts_lock:
        return {"alerts": list(live_alerts)}


@app.get("/live/status")
def get_live_status():
    return live_status


@app.get("/live/wired-status")
def get_live_wired_status():
    return get_wired_connection_status()


@app.post("/live/start", response_model=LiveCaptureResponse)
def start_live_capture():
    if live_status["running"]:
        return LiveCaptureResponse(status="ok", message="Live capture already running")

    live_detector.start()
    return LiveCaptureResponse(status="ok", message="Live capture started")


@app.post("/live/stop", response_model=LiveCaptureResponse)
def stop_live_capture():
    if not live_status["running"]:
        return LiveCaptureResponse(status="ok", message="Live capture already stopped")

    live_detector.stop()
    return LiveCaptureResponse(status="ok", message="Live capture stopped")


@app.websocket("/ws/live-alerts")
async def live_alert_socket(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)

    with alerts_lock:
        snapshot = list(live_alerts)

    await websocket.send_json({"type": "snapshot", "data": snapshot})

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
    except Exception:
        connected_clients.discard(websocket)


@app.get("/attacker-profiles")
def get_attacker_profiles():
    alerts = load_alerts_dataframe(include_benign=False)
    data = build_attacker_profiles(alerts)

    if data.empty:
        return {"message": "No attacker profiles derived from intrusion alerts yet.", "profiles": []}

    PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
    data.to_csv(PROFILES_FILE, index=False)

    return {"profiles": data.to_dict(orient="records")}


@app.get("/attack-summary")
def get_attack_summary():
    alerts = load_alerts_dataframe(include_benign=False)
    data = build_attacker_profiles(alerts)

    if data.empty:
        return {
            "total_attackers": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0
        }

    return {
        "total_attackers": len(data),
        "high_severity": int((data["campaign_severity"] == "HIGH").sum()),
        "medium_severity": int((data["campaign_severity"] == "MEDIUM").sum()),
        "low_severity": int((data["campaign_severity"] == "LOW").sum())
    }

@app.get("/attack-graph")
def get_attack_graph():
    data = load_alerts_dataframe(include_benign=False)

    if data.empty:
        return {"nodes": [], "edges": []}

    nodes = {}
    edges = []

    for _, row in data.iterrows():
        source_ip = row["source_ip"]
        destination_ip = row["destination_ip"]
        attack_type = row["attack_type"]
        confidence = float(row["confidence"])

        if source_ip not in nodes:
            nodes[source_ip] = {
                "id": source_ip,
                "label": source_ip,
                "type": "source"
            }

        if destination_ip not in nodes:
            nodes[destination_ip] = {
                "id": destination_ip,
                "label": destination_ip,
                "type": "destination"
            }

        edges.append({
            "source": source_ip,
            "target": destination_ip,
            "attack_type": attack_type,
            "confidence": confidence
        })

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }


@app.post("/trace-alert")
def trace_alert(alert: AlertTraceInput):
    try:
        flows = pd.read_csv("data/flow_features.csv")
    except FileNotFoundError:
        return {"error": "flow_features.csv not found"}

    required_columns = [
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Protocol",
        "Total Packets",
        "Total Bytes",
        "Average Packet Length",
        "Max Packet Length",
        "Min Packet Length",
    ]

    missing = [col for col in required_columns if col not in flows.columns]
    if missing:
        return {"error": f"Missing columns in flow_features.csv: {missing}"}

    flows["Source IP"] = flows["Source IP"].astype(str).str.strip()
    flows["Destination IP"] = flows["Destination IP"].astype(str).str.strip()

    source_ip = str(alert.source_ip).strip()
    destination_ip = str(alert.destination_ip).strip()

    matched = flows[
        (flows["Source IP"] == source_ip) |
        (flows["Destination IP"] == source_ip) |
        (flows["Source IP"] == destination_ip) |
        (flows["Destination IP"] == destination_ip)
    ]

    print("TRACE REQUEST:", source_ip, destination_ip)
    print("MATCHED ROWS:", len(matched))

    if matched.empty:
        return {"error": "No related flow found for this alert"}

    row = matched.iloc[-1]

    top_features = [
    {"name": "Total Bytes", "value": float(row["Total Bytes"])},
    {"name": "Total Packets", "value": float(row["Total Packets"])},
    {"name": "Avg Packet Length", "value": float(row["Average Packet Length"])},
    {"name": "Max Packet Length", "value": float(row["Max Packet Length"])},
    {"name": "Min Packet Length", "value": float(row["Min Packet Length"])},
    
    ]

    return {
        "source_ip": str(source_ip),
        "destination_ip": str(destination_ip),
        "attack_type": str(alert.attack_type) if alert.attack_type is not None else "",
        "source_port": int(row["Source Port"]),
        "destination_port": int(row["Destination Port"]),
        "protocol": str(row["Protocol"]),
        "predicted_attack": str(alert.attack_type) if alert.attack_type is not None else "",
        "confidence": 100,
        "top_features": top_features,
        "flow_summary": {
            "total_packets": int(row["Total Packets"]),
            "total_bytes": int(row["Total Bytes"]),
            "average_packet_length": float(row["Average Packet Length"]),
            "max_packet_length": float(row["Max Packet Length"]),
            "min_packet_length": float(row["Min Packet Length"]),
        }
    }

@app.get("/grouped-attacks")
def grouped_attacks():
    try:
        alerts = pd.read_csv("data/intrusion_alerts.csv")
    except FileNotFoundError:
        return {"groups": []}

    if alerts.empty:
        return {"groups": []}

    alerts["source_ip"] = alerts["source_ip"].astype(str).str.strip()

    grouped = (
        alerts.groupby("source_ip")
        .agg(
            attack_count=("attack_type", "count"),
            attack_types=("attack_type", lambda x: list(set(x)))
        )
        .reset_index()
    )

    return {
        "groups": grouped.to_dict(orient="records")
    }