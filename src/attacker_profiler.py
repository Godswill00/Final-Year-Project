import pandas as pd
from collections import defaultdict

ALERT_FILE = "data/intrusion_alerts.csv"
OUTPUT_FILE = "data/attacker_profiles.csv"

try:
    data = pd.read_csv(ALERT_FILE)
except FileNotFoundError:
    print("No intrusion_alerts.csv file found yet.")
    exit()

if data.empty:
    print("Alert file exists but contains no alerts yet.")
    exit()

profiles = defaultdict(lambda: {
    "total_alerts": 0,
    "targets": set(),
    "attack_types": set(),
    "total_confidence": 0.0
})

for _, row in data.iterrows():
    source_ip = row["source_ip"]
    destination_ip = row["destination_ip"]
    attack_type = row["attack_type"]
    confidence = float(row["confidence"])

    profiles[source_ip]["total_alerts"] += 1
    profiles[source_ip]["targets"].add(destination_ip)
    profiles[source_ip]["attack_types"].add(attack_type)
    profiles[source_ip]["total_confidence"] += confidence

profile_rows = []

for source_ip, info in profiles.items():
    total_alerts = info["total_alerts"]
    targets_hit = len(info["targets"])
    attack_types = ", ".join(sorted(info["attack_types"]))
    average_confidence = info["total_confidence"] / total_alerts

    if total_alerts >= 10 or targets_hit >= 5:
        severity = "HIGH"
    elif total_alerts >= 5 or targets_hit >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    profile_rows.append({
        "source_ip": source_ip,
        "total_alerts": total_alerts,
        "targets_hit": targets_hit,
        "target_list": ", ".join(sorted(info["targets"])),
        "attack_types": attack_types,
        "average_confidence": round(average_confidence, 2),
        "campaign_severity": severity
    })

profile_df = pd.DataFrame(profile_rows)
profile_df = profile_df.sort_values(by=["campaign_severity", "total_alerts"], ascending=[True, False])

profile_df.to_csv(OUTPUT_FILE, index=False)

print("=== ATTACKER PROFILES ===\n")
print(profile_df)
print(f"\nAttacker profiles saved to {OUTPUT_FILE}")