from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
from pathlib import Path

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained model
model = joblib.load("model/intrusion_model.pkl")
ALERTS_FILE = Path("data/intrusion_alerts.csv")
PROFILES_FILE = Path("data/attacker_profiles.csv")


class TrafficInput(BaseModel):
    Destination_Port: float
    Flow_Duration: float
    Total_Fwd_Packets: float
    Total_Length_of_Fwd_Packets: float
    Fwd_Packet_Length_Max: float
    Fwd_Packet_Length_Min: float
    Fwd_Packet_Length_Mean: float
    Fwd_Packet_Length_Std: float
    Bwd_Packet_Length_Max: float
    Bwd_Packet_Length_Min: float
    Bwd_Packet_Length_Mean: float
    Bwd_Packet_Length_Std: float
    Flow_Bytes_s: float
    Flow_Packets_s: float
    Flow_IAT_Mean: float
    Flow_IAT_Std: float
    Flow_IAT_Max: float
    Flow_IAT_Min: float
    Fwd_IAT_Total: float
    Fwd_IAT_Mean: float
    Fwd_IAT_Std: float
    Fwd_IAT_Max: float
    Fwd_IAT_Min: float
    Bwd_IAT_Total: float
    Bwd_IAT_Mean: float
    Bwd_IAT_Std: float
    Bwd_IAT_Max: float
    Bwd_IAT_Min: float
    Fwd_Header_Length: float
    Bwd_Header_Length: float
    Fwd_Packets_s: float
    Bwd_Packets_s: float
    Min_Packet_Length: float
    Max_Packet_Length: float
    Packet_Length_Mean: float
    Packet_Length_Std: float
    Packet_Length_Variance: float
    FIN_Flag_Count: float
    PSH_Flag_Count: float
    ACK_Flag_Count: float
    Average_Packet_Size: float
    Subflow_Fwd_Bytes: float
    Init_Win_bytes_forward: float
    Init_Win_bytes_backward: float
    act_data_pkt_fwd: float
    min_seg_size_forward: float
    Active_Mean: float
    Active_Max: float
    Active_Min: float
    Idle_Mean: float
    Idle_Max: float
    Idle_Min: float


@app.get("/")
def home():
    return {"message": "Network Intrusion Detection API running"}


@app.post("/predict")
def predict_attack(traffic: TrafficInput):
    input_data = pd.DataFrame([{
        "Destination Port": traffic.Destination_Port,
        "Flow Duration": traffic.Flow_Duration,
        "Total Fwd Packets": traffic.Total_Fwd_Packets,
        "Total Length of Fwd Packets": traffic.Total_Length_of_Fwd_Packets,
        "Fwd Packet Length Max": traffic.Fwd_Packet_Length_Max,
        "Fwd Packet Length Min": traffic.Fwd_Packet_Length_Min,
        "Fwd Packet Length Mean": traffic.Fwd_Packet_Length_Mean,
        "Fwd Packet Length Std": traffic.Fwd_Packet_Length_Std,
        "Bwd Packet Length Max": traffic.Bwd_Packet_Length_Max,
        "Bwd Packet Length Min": traffic.Bwd_Packet_Length_Min,
        "Bwd Packet Length Mean": traffic.Bwd_Packet_Length_Mean,
        "Bwd Packet Length Std": traffic.Bwd_Packet_Length_Std,
        "Flow Bytes/s": traffic.Flow_Bytes_s,
        "Flow Packets/s": traffic.Flow_Packets_s,
        "Flow IAT Mean": traffic.Flow_IAT_Mean,
        "Flow IAT Std": traffic.Flow_IAT_Std,
        "Flow IAT Max": traffic.Flow_IAT_Max,
        "Flow IAT Min": traffic.Flow_IAT_Min,
        "Fwd IAT Total": traffic.Fwd_IAT_Total,
        "Fwd IAT Mean": traffic.Fwd_IAT_Mean,
        "Fwd IAT Std": traffic.Fwd_IAT_Std,
        "Fwd IAT Max": traffic.Fwd_IAT_Max,
        "Fwd IAT Min": traffic.Fwd_IAT_Min,
        "Bwd IAT Total": traffic.Bwd_IAT_Total,
        "Bwd IAT Mean": traffic.Bwd_IAT_Mean,
        "Bwd IAT Std": traffic.Bwd_IAT_Std,
        "Bwd IAT Max": traffic.Bwd_IAT_Max,
        "Bwd IAT Min": traffic.Bwd_IAT_Min,
        "Fwd Header Length": traffic.Fwd_Header_Length,
        "Bwd Header Length": traffic.Bwd_Header_Length,
        "Fwd Packets/s": traffic.Fwd_Packets_s,
        "Bwd Packets/s": traffic.Bwd_Packets_s,
        "Min Packet Length": traffic.Min_Packet_Length,
        "Max Packet Length": traffic.Max_Packet_Length,
        "Packet Length Mean": traffic.Packet_Length_Mean,
        "Packet Length Std": traffic.Packet_Length_Std,
        "Packet Length Variance": traffic.Packet_Length_Variance,
        "FIN Flag Count": traffic.FIN_Flag_Count,
        "PSH Flag Count": traffic.PSH_Flag_Count,
        "ACK Flag Count": traffic.ACK_Flag_Count,
        "Average Packet Size": traffic.Average_Packet_Size,
        "Subflow Fwd Bytes": traffic.Subflow_Fwd_Bytes,
        "Init_Win_bytes_forward": traffic.Init_Win_bytes_forward,
        "Init_Win_bytes_backward": traffic.Init_Win_bytes_backward,
        "act_data_pkt_fwd": traffic.act_data_pkt_fwd,
        "min_seg_size_forward": traffic.min_seg_size_forward,
        "Active Mean": traffic.Active_Mean,
        "Active Max": traffic.Active_Max,
        "Active Min": traffic.Active_Min,
        "Idle Mean": traffic.Idle_Mean,
        "Idle Max": traffic.Idle_Max,
        "Idle Min": traffic.Idle_Min
    }])

    prediction = model.predict(input_data)[0]

    probabilities = model.predict_proba(input_data)[0]
    confidence = float(max(probabilities)) * 100

    feature_importances = model.feature_importances_
    feature_names = input_data.columns

    feature_scores = []
    for feature_name, importance in zip(feature_names, feature_importances):
        value = input_data.iloc[0][feature_name]
        score = abs(value) * importance
        feature_scores.append((feature_name, float(value), float(importance), float(score)))

    feature_scores.sort(key=lambda x: x[3], reverse=True)
    top_features = [item[0] for item in feature_scores[:5]]

    return {
        "predicted_attack": prediction,
        "confidence": round(confidence, 2),
        "top_features": top_features
    }

@app.get("/alerts")
def get_alerts():
    if not ALERTS_FILE.exists():
        return {"message": "No alerts file found yet.", "alerts": []}

    data = pd.read_csv(ALERTS_FILE)

    if data.empty:
        return {"message": "Alerts file is empty.", "alerts": []}

    return {"alerts": data.to_dict(orient="records")}


@app.get("/attacker-profiles")
def get_attacker_profiles():
    if not PROFILES_FILE.exists():
        return {"message": "No attacker profiles file found yet.", "profiles": []}

    data = pd.read_csv(PROFILES_FILE)

    if data.empty:
        return {"message": "Attacker profiles file is empty.", "profiles": []}

    return {"profiles": data.to_dict(orient="records")}


@app.get("/attack-summary")
def get_attack_summary():
    if not PROFILES_FILE.exists():
        return {
            "total_attackers": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0
        }

    data = pd.read_csv(PROFILES_FILE)

    if data.empty:
        return {
            "total_attackers": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0
        }

    return {
        "total_attackers": len(data),
        "high_severity": int((data["campaign_severity"] == "HIGH").sum()),
        "medium_severity": int((data["campaign_severity"] == "MEDIUM").sum()),
        "low_severity": int((data["campaign_severity"] == "LOW").sum())
    }

@app.get("/attack-graph")
def get_attack_graph():
    if not ALERTS_FILE.exists():
        return {"nodes": [], "edges": []}

    data = pd.read_csv(ALERTS_FILE)

    if data.empty:
        return {"nodes": [], "edges": []}

    nodes = {}
    edges = []

    for _, row in data.iterrows():
        source_ip = row["source_ip"]
        destination_ip = row["destination_ip"]
        attack_type = row["attack_type"]
        confidence = float(row["confidence"])

        if source_ip not in nodes:
            nodes[source_ip] = {
                "id": source_ip,
                "label": source_ip,
                "type": "source"
            }

        if destination_ip not in nodes:
            nodes[destination_ip] = {
                "id": destination_ip,
                "label": destination_ip,
                "type": "destination"
            }

        edges.append({
            "source": source_ip,
            "target": destination_ip,
            "attack_type": attack_type,
            "confidence": confidence
        })

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }
    # prediction = model.predict(input_data)

    # return {"predicted_attack": prediction[0]}