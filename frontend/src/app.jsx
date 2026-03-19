import { useEffect, useState } from "react";
import axios from "axios";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import AttackGraph from "./AttackGraph";
import AttackerProfiles from "./AttackerProfiles";
import AlertStream from "./AlertStream";

function App() {
  const [summary, setSummary] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [displayedAlerts, setDisplayedAlerts] = useState([]);
  const [xaiResult, setXaiResult] = useState(null);
  const [xaiError, setXaiError] = useState("");

  const chartData = [
    { time: "12:00", value: 20 },
    { time: "12:05", value: 35 },
    { time: "12:10", value: 50 },
    { time: "12:15", value: 40 },
    { time: "12:20", value: 60 },
    { time: "12:25", value: 55 },
    { time: "12:30", value: 70 },
  ];

  const runTraceback = async (sourceIp, destinationIp, attackType) => {
    console.log("runTraceback called", sourceIp, destinationIp, attackType);

    try {
      setXaiError("");
      setXaiResult(null);

      const res = await axios.post("http://127.0.0.1:8000/trace-alert", {
        source_ip: sourceIp,
        destination_ip: destinationIp,
        attack_type: attackType,
      });

      if (res.data.error) {
        setXaiError(res.data.error);
        return;
      }

      setXaiResult(res.data);
    } catch (err) {
      console.error(err);
      setXaiError("Traceback failed");
    }
  };

  useEffect(() => {
    const fetchData = () => {
      axios
        .get("http://127.0.0.1:8000/attack-summary")
        .then((res) => setSummary(res.data))
        .catch((err) => console.error(err));

      axios
        .get("http://127.0.0.1:8000/alerts")
        .then((res) => {
          const newAlerts = res.data.alerts || [];
          setAlerts(newAlerts);

          setDisplayedAlerts((prev) => {
            const existingIds = new Set(
              prev.map(
                (a) => `${a.source_ip}-${a.destination_ip}-${a.attack_type}`
              )
            );

            const fresh = newAlerts.filter(
              (a) =>
                !existingIds.has(
                  `${a.source_ip}-${a.destination_ip}-${a.attack_type}`
                )
            );

            return [...fresh, ...prev].slice(0, 10);
          });
        })
        .catch((err) => console.error(err));
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      <div className="sidebar">
        <h2>🛡️ TraceGuard</h2>
        <p className="slogan">Advanced Intelligence • Proven Evidence</p>
        <div className="sidebar-item">Dashboard</div>
        <div className="sidebar-item">Alerts</div>
        <div className="sidebar-item">Topology</div>
        <div className="sidebar-item">Traceback</div>
      </div>

      <div className="main">
        <div className="topbar">
          <input className="search" placeholder="Enter IP, Domain..." />
          <div className="status">● System Operational</div>
        </div>

        <div className="cards">
          <div className="card">
            <h4>Total Attackers</h4>
            <h2>{summary.total_attackers || 0}</h2>
            <div className="progress green"></div>
          </div>

          <div className="card">
            <h4>High Severity</h4>
            <h2>{summary.high_severity || 0}</h2>
            <div className="progress red"></div>
          </div>

          <div className="card">
            <h4>Medium Severity</h4>
            <h2>{summary.medium_severity || 0}</h2>
            <div className="progress blue"></div>
          </div>

          <div className="card">
            <h4>Low Severity</h4>
            <h2>{summary.low_severity || 0}</h2>
            <div className="progress yellow"></div>
          </div>
        </div>

        <div className="card" style={{ marginTop: "20px" }}>
          <h3>Network Throughput</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={chartData}>
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Line
                type="monotone"
                dataKey="value"
                stroke="#38bdf8"
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <AttackGraph alerts={alerts} />

        <AttackerProfiles />

        <button
          type="button"
          onClick={() => alert("Test button works")}
          style={{
            padding: "10px 14px",
            marginTop: "20px",
            marginBottom: "12px",
            cursor: "pointer",
            position: "relative",
            zIndex: 10000,
          }}
        >
          Test Click
        </button>

        <AlertStream
          alerts={displayedAlerts}
          runTraceback={runTraceback}
        />

        {(xaiResult || xaiError) && (
          <div className="card" style={{ marginTop: "20px" }}>
            <h3>Traceback / XAI Result</h3>

            {xaiError && <p>{xaiError}</p>}

            {xaiResult && (
              <div>
                <p>
                  <strong>Attack Type:</strong> {xaiResult.predicted_attack}
                </p>
                <p>
                  <strong>Source:</strong> {xaiResult.source_ip}
                </p>
                <p>
                  <strong>Destination:</strong> {xaiResult.destination_ip}
                </p>
                <p>
                  <strong>Protocol:</strong> {xaiResult.protocol}
                </p>
                <p>
                  <strong>Source Port:</strong> {xaiResult.source_port}
                </p>
                <p>
                  <strong>Destination Port:</strong> {xaiResult.destination_port}
                </p>

                {xaiResult.flow_summary && (
                  <div>
                    <p>
                      <strong>Total Packets:</strong>{" "}
                      {xaiResult.flow_summary.total_packets}
                    </p>
                    <p>
                      <strong>Total Bytes:</strong>{" "}
                      {xaiResult.flow_summary.total_bytes}
                    </p>
                    <p>
                      <strong>Average Packet Length:</strong>{" "}
                      {xaiResult.flow_summary.average_packet_length}
                    </p>
                    <p>
                      <strong>Max Packet Length:</strong>{" "}
                      {xaiResult.flow_summary.max_packet_length}
                    </p>
                    <p>
                      <strong>Min Packet Length:</strong>{" "}
                      {xaiResult.flow_summary.min_packet_length}
                    </p>
                  </div>
                )}

                {xaiResult.top_features && (
                  <div>
                    <strong>Key Features:</strong>
                    <ul>
                      {xaiResult.top_features.map((feature, index) => (
                        <li key={index}>{feature}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;