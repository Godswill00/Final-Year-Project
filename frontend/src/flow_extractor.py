from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import pandas as pd
import time

flows = defaultdict(lambda: {
    "Source IP": "",
    "Destination IP": "",
    "Source Port": 0,
    "Destination Port": 0,
    "Protocol": "",
    "Total Packets": 0,
    "Total Bytes": 0,
    "Packet Lengths": []
})

OUTPUT_FILE = "data/flow_features.csv"


def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_len = len(packet)

    src_port = 0
    dst_port = 0
    protocol_name = "OTHER"

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol_name = "TCP"
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol_name = "UDP"

    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol_name)

    flows[flow_key]["Source IP"] = src_ip
    flows[flow_key]["Destination IP"] = dst_ip
    flows[flow_key]["Source Port"] = src_port
    flows[flow_key]["Destination Port"] = dst_port
    flows[flow_key]["Protocol"] = protocol_name
    flows[flow_key]["Total Packets"] += 1
    flows[flow_key]["Total Bytes"] += packet_len
    flows[flow_key]["Packet Lengths"].append(packet_len)


def save_flows():
    records = []

    for _, flow in flows.items():
        lengths = flow["Packet Lengths"]
        if not lengths:
            continue

        records.append({
            "Source IP": flow["Source IP"],
            "Destination IP": flow["Destination IP"],
            "Source Port": flow["Source Port"],
            "Destination Port": flow["Destination Port"],
            "Protocol": flow["Protocol"],
            "Total Packets": flow["Total Packets"],
            "Total Bytes": flow["Total Bytes"],
            "Average Packet Length": sum(lengths) / len(lengths),
            "Max Packet Length": max(lengths),
            "Min Packet Length": min(lengths),
        })

    df = pd.DataFrame(records)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"Saved {len(records)} flows to {OUTPUT_FILE}")


def start_flow_capture(duration=30):
    print(f"Capturing packets for {duration} seconds...")
    sniff(prn=process_packet, store=False, timeout=duration)
    save_flows()


if __name__ == "__main__":
    start_flow_capture()