from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import joblib
import pandas as pd
import numpy as np
from alert_logger import log_alert
from xai_explainer import explain_prediction
# Load trained model
model = joblib.load("model/intrusion_model.pkl")

# Exact feature order used by the trained model
FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "PSH Flag Count",
    "ACK Flag Count", "Average Packet Size", "Subflow Fwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Max", "Active Min",
    "Idle Mean", "Idle Max", "Idle Min"
]

flows = defaultdict(lambda: {
    "start_time": None,
    "end_time": None,
    "packet_lengths": [],
    "timestamps": [],
    "total_fwd_packets": 0,
    "total_fwd_bytes": 0
})


def safe_std(values):
    if len(values) < 2:
        return 0.0
    return float(np.std(values))


def safe_var(values):
    if len(values) < 2:
        return 0.0
    return float(np.var(values))


def build_feature_row(flow_key, flow_data):
    src_ip, dst_ip, src_port, dst_port, protocol = flow_key

    start_time = flow_data["start_time"]
    end_time = flow_data["end_time"]
    duration = max((end_time - start_time).total_seconds() * 1_000_000, 1)

    total_fwd_packets = flow_data["total_fwd_packets"]
    total_fwd_bytes = flow_data["total_fwd_bytes"]
    packet_lengths = flow_data["packet_lengths"]
    timestamps = flow_data["timestamps"]

    max_len = max(packet_lengths) if packet_lengths else 0
    min_len = min(packet_lengths) if packet_lengths else 0
    mean_len = float(np.mean(packet_lengths)) if packet_lengths else 0
    std_len = safe_std(packet_lengths)
    var_len = safe_var(packet_lengths)

    seconds = max(duration / 1_000_000, 0.000001)
    flow_bytes_s = total_fwd_bytes / seconds
    flow_packets_s = total_fwd_packets / seconds

    iats = []
    if len(timestamps) >= 2:
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds() * 1_000_000
            iats.append(delta)

    flow_iat_mean = float(np.mean(iats)) if iats else 0
    flow_iat_std = safe_std(iats)
    flow_iat_max = max(iats) if iats else 0
    flow_iat_min = min(iats) if iats else 0

    row = {
        "Destination Port": dst_port,
        "Flow Duration": duration,
        "Total Fwd Packets": total_fwd_packets,
        "Total Length of Fwd Packets": total_fwd_bytes,
        "Fwd Packet Length Max": max_len,
        "Fwd Packet Length Min": min_len,
        "Fwd Packet Length Mean": mean_len,
        "Fwd Packet Length Std": std_len,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0,
        "Bwd Packet Length Std": 0,
        "Flow Bytes/s": flow_bytes_s,
        "Flow Packets/s": flow_packets_s,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,
        "Fwd IAT Total": duration,
        "Fwd IAT Mean": flow_iat_mean,
        "Fwd IAT Std": flow_iat_std,
        "Fwd IAT Max": flow_iat_max,
        "Fwd IAT Min": flow_iat_min,
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
        "Packet Length Std": std_len,
        "Packet Length Variance": var_len,
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

    df = pd.DataFrame([row])[FEATURE_COLUMNS]

    trace_info = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol
    }

    return df, trace_info, row


def explain_prediction(feature_row_dict, top_n=5):
    importances = model.feature_importances_
    feature_scores = []

    for feature_name, importance in zip(FEATURE_COLUMNS, importances):
        value = feature_row_dict.get(feature_name, 0)
        score = abs(value) * importance
        feature_scores.append((feature_name, value, importance, score))

    feature_scores.sort(key=lambda x: x[3], reverse=True)
    return feature_scores[:top_n]


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
    flow["timestamps"].append(now)
    flow["total_fwd_packets"] += 1
    flow["total_fwd_bytes"] += pkt_len

    if flow["total_fwd_packets"] >= 5:
        feature_df, trace_info, feature_row_dict = build_feature_row(flow_key, flow)

        try:
            prediction = model.predict(feature_df)[0]
            probabilities = model.predict_proba(feature_df)[0]
            class_names = model.classes_
            confidence = float(np.max(probabilities)) * 100

            # print(f"Checked flow: {trace_info['source_ip']} -> {trace_info['destination_ip']} | Prediction: {prediction}")

            # only alert on suspicious traffic
            if prediction != "Normal Traffic":
                if prediction != "Normal Traffic":

                    top_features = explain_prediction(feature_df)
                    print("\nSHAP Explanation:")
                    for feature, value in top_features:
                        print(f"{feature}: {value:.4f}")

                    feature_names_only = [feature for feature, value in top_features]

                    print("\n🚨 INTRUSION ALERT 🚨")
                    print(f"Prediction: {prediction}")
                    print(f"Confidence: {confidence:.2f}%")

                    print("\nTRACEBACK INFORMATION")
                    print(f"Source IP: {trace_info['source_ip']}")
                    print(f"Destination IP: {trace_info['destination_ip']}")
                    print(f"Source Port: {trace_info['source_port']}")
                    print(f"Destination Port: {trace_info['destination_port']}")
                    print(f"Protocol: {trace_info['protocol']}")

                    print("\nFLOW STATISTICS")
                    print(f"Packets in Flow: {flow['total_fwd_packets']}")
                    print(f"Bytes in Flow: {flow['total_fwd_bytes']}")

                    top_features = explain_prediction(feature_df)

                    print("\nSHAP Explanation:")
                    for feature, value in top_features:
                        print(f"{feature}: {value:.4f}")

                    feature_names_only = [feature for feature, value in top_features]


                log_alert(
                    attack_type=prediction,
                    confidence=confidence,
                    source_ip=trace_info["source_ip"],
                    destination_ip=trace_info["destination_ip"],
                    source_port=trace_info["source_port"],
                    destination_port=trace_info["destination_port"],
                    protocol=trace_info["protocol"],
                    packets_in_flow=flow["total_fwd_packets"],
                    bytes_in_flow=flow["total_fwd_bytes"],
                    top_trigger_features=feature_names_only
                )

                print("=" * 40)

        except Exception as e:
            print(f"Prediction error: {e}")


print("Starting real-time intrusion detection with XAI... Press Ctrl + C to stop.")
sniff(prn=process_packet, store=False)
