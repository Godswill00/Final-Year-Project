from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import joblib
import pandas as pd

# Load trained model
model = joblib.load("model/intrusion_model.pkl")

# Store flows
flows = defaultdict(lambda: {
    "start_time": None,
    "end_time": None,
    "packet_lengths": [],
    "total_fwd_packets": 0,
    "total_fwd_bytes": 0
})

def build_feature_row(flow_key, flow_data):
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

    # Build a row with the same columns your model expects
    # Unknown live values are temporarily filled with 0
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
        "Idle Min": 0
    }

    return pd.DataFrame([row]), {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol
    }

def process_packet(packet):
    if IP not in packet:
        return

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
    now = datetime.now()
    pkt_len = len(packet)

    flow = flows[flow_key]
    if flow["start_time"] is None:
        flow["start_time"] = now
    flow["end_time"] = now
    flow["packet_lengths"].append(pkt_len)
    flow["total_fwd_packets"] += 1
    flow["total_fwd_bytes"] += pkt_len

    # Only predict after at least 5 packets in a flow
    if flow["total_fwd_packets"] >= 5:
        feature_df, trace_info = build_feature_row(flow_key, flow)

        try:
            prediction = model.predict(feature_df)[0]

            print("\n=== TRAFFIC ANALYSIS ===")
            print(f"Prediction: {prediction}")
            print(f"Source IP: {trace_info['source_ip']}")
            print(f"Destination IP: {trace_info['destination_ip']}")
            print(f"Source Port: {trace_info['source_port']}")
            print(f"Destination Port: {trace_info['destination_port']}")
            print(f"Protocol: {trace_info['protocol']}")
            print(f"Packets in Flow: {flow['total_fwd_packets']}")
            print(f"Bytes in Flow: {flow['total_fwd_bytes']}")
            print("=" * 30)

        except Exception as e:
            print(f"Prediction error: {e}")

print("Starting real-time intrusion detection... Press Ctrl + C to stop.")
sniff(prn=process_packet, store=False)
