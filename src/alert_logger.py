import csv
import os
from datetime import datetime

ALERT_FILE = "data/intrusion_alerts.csv"

def log_alert(
    attack_type,
    confidence,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    packets_in_flow,
    bytes_in_flow,
    top_trigger_features
):

    file_exists = os.path.isfile(ALERT_FILE)

    with open(ALERT_FILE, "a", newline="") as f:

        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "timestamp",
                "attack_type",
                "confidence",
                "source_ip",
                "destination_ip",
                "source_port",
                "destination_port",
                "protocol",
                "packets_in_flow",
                "bytes_in_flow",
                "top_trigger_features"
            ])

        writer.writerow([
            datetime.now(),
            attack_type,
            confidence,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            packets_in_flow,
            bytes_in_flow,
            "|".join(top_trigger_features)
        ])
