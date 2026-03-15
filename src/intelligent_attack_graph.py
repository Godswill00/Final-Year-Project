import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from collections import Counter

ALERT_FILE = "data/intrusion_alerts.csv"
OUTPUT_IMAGE = "data/intelligent_attack_graph.png"

try:
    data = pd.read_csv(ALERT_FILE)
except FileNotFoundError:
    print("No intrusion_alerts.csv file found yet.")
    exit()

if data.empty:
    print("Alert file exists but contains no alerts yet.")
    exit()

G = nx.DiGraph()

source_counts = Counter(data["source_ip"])
destination_counts = Counter(data["destination_ip"])

for _, row in data.iterrows():
    source_ip = row["source_ip"]
    destination_ip = row["destination_ip"]
    attack_type = row["attack_type"]
    confidence = row["confidence"]

    G.add_node(source_ip, node_type="source", weight=source_counts[source_ip])
    G.add_node(destination_ip, node_type="destination", weight=destination_counts[destination_ip])

    if G.has_edge(source_ip, destination_ip):
        existing_label = G[source_ip][destination_ip]["label"]
        G[source_ip][destination_ip]["label"] = existing_label + f", {attack_type}"
        G[source_ip][destination_ip]["count"] += 1
    else:
        G.add_edge(
            source_ip,
            destination_ip,
            label=attack_type,
            count=1,
            confidence=float(confidence)
        )

plt.figure(figsize=(15, 10))
pos = nx.spring_layout(G, seed=42, k=1.4)

source_nodes = [node for node, attr in G.nodes(data=True) if attr["node_type"] == "source"]
destination_nodes = [node for node, attr in G.nodes(data=True) if attr["node_type"] == "destination"]

source_sizes = [1200 + G.nodes[node]["weight"] * 400 for node in source_nodes]
destination_sizes = [1200 + G.nodes[node]["weight"] * 250 for node in destination_nodes]

nx.draw_networkx_nodes(G, pos, nodelist=source_nodes, node_size=source_sizes)
nx.draw_networkx_nodes(G, pos, nodelist=destination_nodes, node_size=destination_sizes)

nx.draw_networkx_labels(G, pos, font_size=8)

edge_widths = [1 + G[u][v]["count"] for u, v in G.edges()]
nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle="->", arrowsize=20, width=edge_widths)

edge_labels = {(u, v): f"{d['label']} | x{d['count']}" for u, v, d in G.edges(data=True)}
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7)

plt.title("Intelligent Attack Campaign Graph")
plt.axis("off")
plt.tight_layout()
plt.savefig(OUTPUT_IMAGE, dpi=300)
plt.show()

print(f"Intelligent attack graph saved to {OUTPUT_IMAGE}")

print("\n=== CAMPAIGN SUMMARY ===")
for node in source_nodes:
    targets = list(G.successors(node))
    if len(targets) > 1:
        print(f"{node} targeted {len(targets)} systems: {', '.join(targets)}")