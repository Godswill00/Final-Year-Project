from scapy.all import sniff, IP, TCP, UDP
import csv

captured_packets = []

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)

        src_port = 0
        dst_port = 0
        protocol_name = f"IP_PROTO_{proto}"

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"

        packet_info = {
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol_name,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Packet Length": length
        }

        captured_packets.append(packet_info)
        print(packet_info)

print("Starting packet capture... Press Ctrl + C to stop.")
sniff(prn=process_packet, count=20)

with open("data/captured_packets.csv", "w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=[
        "Source IP",
        "Destination IP",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Packet Length"
    ])
    writer.writeheader()
    writer.writerows(captured_packets)

print("Captured packets saved to data/captured_packets.csv")