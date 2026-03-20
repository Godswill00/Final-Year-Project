import { useEffect, useState } from "react";
import axios from "axios";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

function AttackTimeline() {
  const [timelineData, setTimelineData] = useState([]);

  useEffect(() => {
    axios
      .get("http://127.0.0.1:8000/alerts")
      .then((res) => {
        const alerts = res.data.alerts || [];

        const grouped = alerts.map((alert, index) => ({
          time: `T${index + 1}`,
          count: 1,
          attack_type: alert.attack_type,
        }));

        setTimelineData(grouped);
      })
      .catch((err) => console.error(err));
  }, []);

  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h3>Attack Timeline</h3>
      <div style={{ height: 260 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={timelineData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#e5e7eb" />
            <YAxis stroke="#e5e7eb" />
            <Tooltip />
            <Line
              type="monotone"
              dataKey="count"
              stroke="#38bdf8"
              strokeWidth={3}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default AttackTimeline;