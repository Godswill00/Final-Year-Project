from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_len = len(packet)

        src_port = None
        dst_port = None
        protocol_name = "OTHER"

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"

        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] "
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
            f"{protocol_name} | Length={packet_len}"
        )


def start_sniffing():
    print("Starting live packet capture... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_sniffing()