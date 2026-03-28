import { useEffect, useState } from "react";
import axios from "axios";

function AttackerProfiles() {
  const [profiles, setProfiles] = useState([]);

  useEffect(() => {
    const fetchProfiles = () => {
      axios
        .get("http://127.0.0.1:8000/attacker-profiles")
        .then((res) => {
          setProfiles(res.data.profiles || []);
        })
        .catch((err) => console.error(err));
    };

    fetchProfiles();
    const interval = setInterval(fetchProfiles, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h3>Attacker Profiles</h3>

      {profiles.length === 0 && <p>No attacker profiles yet.</p>}

      {profiles.map((p, i) => (
        <div key={i} className="attacker-profile-item">
          <strong>Source IP:</strong> {p.source_ip} <br />

          <strong>Attack Types:</strong> {p.attack_types} <br />

          <strong>Total Alerts:</strong> {p.total_alerts} <br />

          <strong>Targets:</strong> {p.targets} <br />

          <strong>Avg Confidence:</strong> {p.average_confidence}% <br />

          <strong>Severity:</strong> {p.campaign_severity}
        </div>
      ))}
    </div>
  );
}

export default AttackerProfiles;