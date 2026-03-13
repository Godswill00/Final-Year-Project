import pandas as pd

# Load captured packets
data = pd.read_csv("data/captured_packets.csv")

# Group packets into flows using the 5-tuple
flow_groups = data.groupby([
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol"
])

flow_records = []

for flow_key, group in flow_groups:
    src_ip, dst_ip, src_port, dst_port, protocol = flow_key

    total_packets = len(group)
    total_bytes = group["Packet Length"].sum()
    avg_packet_length = group["Packet Length"].mean()
    max_packet_length = group["Packet Length"].max()
    min_packet_length = group["Packet Length"].min()

    flow_record = {
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Source Port": src_port,
        "Destination Port": dst_port,
        "Protocol": protocol,
        "Total Packets": total_packets,
        "Total Bytes": total_bytes,
        "Average Packet Length": avg_packet_length,
        "Max Packet Length": max_packet_length,
        "Min Packet Length": min_packet_length
    }

    flow_records.append(flow_record)

# Convert to DataFrame
flow_df = pd.DataFrame(flow_records)

# Save flows
flow_df.to_csv("data/flow_features.csv", index=False)

print("Flow features created successfully!")
print(flow_df.head())
print("\nSaved to data/flow_features.csv")