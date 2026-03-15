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

print("=== ATTACK CORRELATION ENGINE ===\n")

source_to_targets = defaultdict(set)
source_to_attack_types = defaultdict(set)
source_to_alert_count = defaultdict(int)
source_to_total_confidence = defaultdict(float)

for _, row in data.iterrows():
    source_ip = row["source_ip"]
    destination_ip = row["destination_ip"]
    attack_type = row["attack_type"]
    confidence = float(row["confidence"])

    source_to_targets[source_ip].add(destination_ip)
    source_to_attack_types[source_ip].add(attack_type)
    source_to_alert_count[source_ip] += 1
    source_to_total_confidence[source_ip] += confidence

print("Correlated Attack Sources:\n")

for source_ip in source_to_alert_count:
    alert_count = source_to_alert_count[source_ip]
    targets = source_to_targets[source_ip]
    attack_types = source_to_attack_types[source_ip]
    avg_confidence = source_to_total_confidence[source_ip] / alert_count

    print(f"Source IP: {source_ip}")
    print(f"Total Alerts: {alert_count}")
    print(f"Targets Hit: {len(targets)}")
    print(f"Target List: {', '.join(targets)}")
    print(f"Attack Types: {', '.join(attack_types)}")
    print(f"Average Confidence: {avg_confidence:.2f}")
    
    if len(targets) > 1:
        print("Assessment: Possible multi-target attack campaign")
    elif alert_count > 3:
        print("Assessment: Repeated suspicious behavior from same source")
    else:
        print("Assessment: Isolated suspicious activity")

    print("-" * 50)