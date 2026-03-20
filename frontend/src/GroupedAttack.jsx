import { useEffect, useState } from "react";
import axios from "axios";

function GroupedAttacks() {
  const [groups, setGroups] = useState([]);

  useEffect(() => {
    axios
      .get("http://127.0.0.1:8000/grouped-attacks")
      .then((res) => setGroups(res.data.groups || []))
      .catch((err) => console.error(err));
  }, []);

  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h3>Attack Intelligence (Grouped)</h3>

      {groups.length === 0 ? (
        <p>No grouped attack data</p>
      ) : (
        groups.map((g, index) => (
          <div
            key={index}
            style={{
              background: "#0f172a",
              padding: "10px",
              marginBottom: "10px",
              borderRadius: "8px",
            }}
          >
            <p><strong>Source:</strong> {g.source_ip}</p>
            <p><strong>Total Attacks:</strong> {g.attack_count}</p>
            <p><strong>Types:</strong> {g.attack_types.join(", ")}</p>
          </div>
        ))
      )}
    </div>
  );
}

export default GroupedAttacks;