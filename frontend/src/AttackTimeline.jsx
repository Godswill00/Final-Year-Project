import { useMemo } from "react";
import {
  AreaChart,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";

function AttackTimeline({ alerts = [] }) {
  const timelineData = useMemo(() => {
    const bucketSizeSeconds = 10;
    const totalBuckets = 30;
    const bucketSizeMs = bucketSizeSeconds * 1000;
    const now = Date.now();
    const endBucket = Math.floor(now / bucketSizeMs) * bucketSizeMs;
    const startBucket = endBucket - (totalBuckets - 1) * bucketSizeMs;

    const buckets = new Map();

    for (let ts = startBucket; ts <= endBucket; ts += bucketSizeMs) {
      buckets.set(ts, {
        eventCount: 0,
        confidenceSum: 0,
        confidenceCount: 0,
      });
    }

    alerts.forEach((alert) => {
      if (!alert.timestamp) return;
      const ts = new Date(alert.timestamp).getTime();
      if (Number.isNaN(ts)) return;

      if (ts < startBucket || ts > endBucket + bucketSizeMs) return;

      const bucketTs = Math.floor(ts / bucketSizeMs) * bucketSizeMs;
      const current = buckets.get(bucketTs);
      if (!current) return;

      current.eventCount += 1;
      if (typeof alert.confidence !== "undefined") {
        current.confidenceSum += Number(alert.confidence || 0);
        current.confidenceCount += 1;
      }

      buckets.set(bucketTs, current);
    });

    const data = Array.from(buckets.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([bucketTs, value]) => ({
        time: new Date(bucketTs).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
        attackRate: Number((value.eventCount / bucketSizeSeconds).toFixed(2)),
        averageConfidence:
          value.confidenceCount > 0
            ? Number((value.confidenceSum / value.confidenceCount).toFixed(2))
            : 0,
      }));

    return data;
  }, [alerts]);

  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h3>Attack Timeline (Live)</h3>
      <div style={{ height: 260 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={timelineData}>
            <defs>
              <linearGradient id="attackRateFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#60a5fa" stopOpacity={0.45} />
                <stop offset="95%" stopColor="#60a5fa" stopOpacity={0.05} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#cbd5e1" />
            <YAxis yAxisId="left" stroke="#93c5fd" width={66} />
            <YAxis yAxisId="right" orientation="right" stroke="#fbbf24" width={66} />
            <Tooltip
              contentStyle={{
                background: "#0f172a",
                border: "1px solid #1f2937",
                borderRadius: "10px",
              }}
            />
            <Legend />
            <Area
              yAxisId="left"
              type="monotone"
              dataKey="attackRate"
              stroke="#60a5fa"
              strokeWidth={2.4}
              fill="url(#attackRateFill)"
              name="Attack Rate (events/s)"
            />
            <Line
              type="monotone"
              yAxisId="right"
              dataKey="averageConfidence"
              stroke="#fbbf24"
              strokeWidth={2}
              dot={false}
              name="Average Confidence (%)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default AttackTimeline;