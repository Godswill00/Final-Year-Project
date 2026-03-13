import pandas as pd
from collections import defaultdict

ALERT_FILE = "data/intrusion_alerts.csv"

try:
    data = pd.read_csv(ALERT_FILE)
except FileNotFoundError:
    print("No intrusion_alerts.csv file found yet.")
    exit()

if data.empty:
    print("Alert file exists but contains no alerts yet.")
    exit()

print("=== ALERT RELATIONSHIP SUMMARY ===\n")

source_attack_counts = data.groupby("source_ip").size().sort_values(ascending=False)
print("Top Alert Sources:")
print(source_attack_counts)
print("\n" + "=" * 50 + "\n")

source_to_targets = defaultdict(set)
source_to_attack_types = defaultdict(set)

for _, row in data.iterrows():
    source_ip = row["source_ip"]
    destination_ip = row["destination_ip"]
    attack_type = row["attack_type"]

    source_to_targets[source_ip].add(destination_ip)
    source_to_attack_types[source_ip].add(attack_type)

print("Source → Target Relationships:")
for source_ip, targets in source_to_targets.items():
    print(f"{source_ip} attacked {len(targets)} target(s): {', '.join(targets)}")

print("\n" + "=" * 50 + "\n")

print("Source → Attack Type Relationships:")
for source_ip, attack_types in source_to_attack_types.items():
    print(f"{source_ip} is associated with: {', '.join(attack_types)}")

print("\n" + "=" * 50 + "\n")

print("Potential Multi-Target Attackers:")
for source_ip, targets in source_to_targets.items():
    if len(targets) > 1:
        print(f"⚠ {source_ip} targeted multiple destinations: {', '.join(targets)}")
