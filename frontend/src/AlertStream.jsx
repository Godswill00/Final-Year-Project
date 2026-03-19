import React from "react";

function AlertStream({ alerts, runTraceback }) {
  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h3>Live Event Stream</h3>

      {alerts.length === 0 && <p>No alerts yet.</p>}

      {alerts.map((a, i) => {
        const severity =
          a.confidence >= 95
            ? "Critical"
            : a.confidence >= 90
            ? "High"
            : a.confidence >= 80
            ? "Medium"
            : "Low";

        const color =
          severity === "Critical"
            ? "#ef4444"
            : severity === "High"
            ? "#facc15"
            : severity === "Medium"
            ? "#38bdf8"
            : "#22c55e";

        return (
          <div
            key={i}
            onClick={() => {
              console.log("CLICK WORKING", a);
              alert(`Clicked: ${a.source_ip}`);
              runTraceback(a.source_ip, a.destination_ip, a.attack_type);
            }}
            style={{
              padding: "12px",
              marginBottom: "10px",
              borderLeft: `4px solid ${color}`,
              background: "#0f172a",
              borderRadius: "6px",
              cursor: "pointer",
            }}
          >
            <strong>
              {severity.toUpperCase()} — {a.attack_type}
            </strong>
            <br />
            SRC: {a.source_ip} → DST: {a.destination_ip}
            <br />
            Confidence: {a.confidence}
          </div>
        );
      })}
    </div>
  );
}

export default AlertStream;