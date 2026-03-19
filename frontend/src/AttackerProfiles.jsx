import { useEffect, useState } from "react";
import axios from "axios";

function AttackerProfiles() {
  const [profiles, setProfiles] = useState([]);

  useEffect(() => {
    axios
      .get("http://127.0.0.1:8000/attacker-profiles")
      .then((res) => {
        setProfiles(res.data.profiles || []);
      })
      .catch((err) => console.error(err));
  }, []);

  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h3>Attacker Profiles</h3>

      {profiles.length === 0 && <p>No attacker profiles yet.</p>}

      {profiles.map((p, i) => (
        <div
          key={i}
          style={{
            padding: "12px",
            marginBottom: "10px",
            borderLeft: "4px solid #38bdf8",
            background: "#0f172a",
            borderRadius: "6px",
          }}
        >
          <strong>Source IP:</strong> {p.source_ip} <br />

          <strong>Attack Types:</strong>{" "}
          {p.attack_types || "N/A"} <br />

          <strong>Total Alerts:</strong>{" "}
          {p.total_alerts || 0} <br />

          <strong>Targets:</strong>{" "}
          {p.targets || "N/A"}
        </div>
      ))}
    </div>
  );
}

export default AttackerProfiles;