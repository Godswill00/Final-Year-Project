import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function XAIChart({ features = [] }) {
  return (
    <div style={{ height: 260, marginTop: "10px" }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={features}>
          <XAxis dataKey="name" stroke="#e5e7eb" />
          <YAxis stroke="#e5e7eb" />
          <Tooltip />
          <Bar dataKey="value" fill="#38bdf8" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default XAIChart;