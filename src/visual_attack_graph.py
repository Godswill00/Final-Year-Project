import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

ALERT_FILE = "data/intrusion_alerts.csv"
OUTPUT_IMAGE = "data/attack_campaign_graph.png"

try:
    data = pd.read_csv(ALERT_FILE)
except FileNotFoundError:
    print("No intrusion_alerts.csv file found yet.")
    exit()

if data.empty:
    print("Alert file exists but contains no alerts yet.")
    exit()

G = nx.DiGraph()

# Add nodes and edges
for _, row in data.iterrows():
    source_ip = row["source_ip"]
    destination_ip = row["destination_ip"]
    attack_type = row["attack_type"]
    confidence = row["confidence"]

    # Mark source and destination node types
    G.add_node(source_ip, node_type="source")
    G.add_node(destination_ip, node_type="destination")

    # Edge label includes attack type
    G.add_edge(source_ip, destination_ip, label=f"{attack_type} ({confidence})")

# Layout
plt.figure(figsize=(14, 10))
pos = nx.spring_layout(G, seed=42, k=1.2)

# Separate node colors by type
source_nodes = [node for node, attr in G.nodes(data=True) if attr["node_type"] == "source"]
destination_nodes = [node for node, attr in G.nodes(data=True) if attr["node_type"] == "destination"]

nx.draw_networkx_nodes(G, pos, nodelist=source_nodes, node_size=2500)
nx.draw_networkx_nodes(G, pos, nodelist=destination_nodes, node_size=2500)

nx.draw_networkx_labels(G, pos, font_size=8)
nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle='->', arrowsize=20)

edge_labels = nx.get_edge_attributes(G, "label")
nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7)

plt.title("Attack Campaign Graph")
plt.axis("off")
plt.tight_layout()
plt.savefig(OUTPUT_IMAGE, dpi=300)
plt.show()

print(f"Attack campaign graph saved to {OUTPUT_IMAGE}")