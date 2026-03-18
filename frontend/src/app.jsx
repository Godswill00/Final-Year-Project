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

  const runTraceback = async (ip) => {
    try {
      setXaiError("");
      setXaiResult(null);

      const res = await axios.post("http://127.0.0.1:8000/predict", {
        source_ip: ip,
      });

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

        <div className="alert-box">
          <h3>Live Event Stream</h3>

          {displayedAlerts.map((a, i) => {
            const severity =
              a.confidence >= 95
                ? "Critical"
                : a.confidence >= 90
                ? "High"
                : a.confidence >= 80
                ? "Medium"
                : "Low";

            const alertClass =
              severity === "Critical"
                ? "alert-red"
                : severity === "High"
                ? "alert-yellow"
                : severity === "Medium"
                ? "alert-blue"
                : "alert-green";

            return (
              <div
                key={i}
                className={`alert-item ${alertClass}`}
                onClick={() => runTraceback(a.source_ip)}
                style={{ cursor: "pointer" }}
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

        {(xaiResult || xaiError) && (
          <div className="card" style={{ marginTop: "20px" }}>
            <h3>Traceback / XAI Result</h3>

            {xaiError && <p>{xaiError}</p>}

            {xaiResult && (
              <div>
                <p>
                  <strong>Predicted Attack:</strong>{" "}
                  {xaiResult.predicted_attack}
                </p>
                <p>
                  <strong>Confidence:</strong> {xaiResult.confidence}
                </p>

                {xaiResult.top_features && (
                  <div>
                    <strong>Top Features:</strong>
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