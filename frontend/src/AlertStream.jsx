import React from "react";

function AlertStream({ alerts, runTraceback, onSignalDashboard }) {
  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h3>Live Event Stream</h3>

      {alerts.length === 0 && <p>No alerts yet.</p>}

      {alerts.map((a, i) => {
        const xaiReasons = String(a.top_trigger_features || "")
          .split("|")
          .map((item) => item.trim())
          .filter(Boolean);

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
              if (onSignalDashboard) onSignalDashboard(a);
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

            <div className="alert-xai-block">
              <small className="alert-xai-title">XAI Reasons:</small>
              {xaiReasons.length > 0 ? (
                <div className="alert-xai-reasons">
                  {xaiReasons.map((reason) => (
                    <span key={`${a.source_ip}-${a.destination_ip}-${reason}`} className="alert-xai-pill">
                      {reason}
                    </span>
                  ))}
                </div>
              ) : (
                <small className="alert-xai-fallback">
                  Explainability details are still being generated for this alert.
                </small>
              )}
            </div>

            <br />
            <small style={{ color: "#94a3b8" }}>
              Click to signal dashboard and inspect traceback
            </small>
          </div>
        );
      })}
    </div>
  );
}

export default AlertStream;