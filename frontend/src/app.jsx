import { useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import {
  AreaChart,
  CartesianGrid,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import AttackGraph from "./AttackGraph";
import AttackerProfiles from "./AttackerProfiles";
import AlertStream from "./AlertStream";
import XAIChart from "./XAIChart";
import GroupedAttack from "./GroupedAttack";
import AttackTimeline from "./AttackTimeline";

function App() {
  const [activeSection, setActiveSection] = useState("dashboard");
  const [summary, setSummary] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [displayedAlerts, setDisplayedAlerts] = useState([]);
  const [dashboardSignal, setDashboardSignal] = useState(null);
  const [unseenDashboardSignals, setUnseenDashboardSignals] = useState(0);
  const [xaiResult, setXaiResult] = useState(null);
  const [xaiError, setXaiError] = useState("");
  const [liveStatus, setLiveStatus] = useState("Connecting...");
  const [liveCaptureStats, setLiveCaptureStats] = useState({
    packets_seen: 0,
    flows_seen: 0,
    running: false,
  });
  const [wiredStatus, setWiredStatus] = useState({
    connected: false,
    interfaces: [],
    reason: "checking",
  });
  const wsRef = useRef(null);
  const activeSectionRef = useRef("dashboard");
  const reconnectTimerRef = useRef(null);
  const heartbeatTimerRef = useRef(null);
  const connectionSeqRef = useRef(0);

  const formatLocalTimeLabel = (timeValue) => {
    const localZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return new Date(timeValue).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZone: localZone,
    });
  };

  const latestForensicPacket = useMemo(() => {
    if (dashboardSignal) return dashboardSignal;
    if (alerts.length === 0) return null;
    return alerts[alerts.length - 1];
  }, [dashboardSignal, alerts]);

  const packetForensics = useMemo(() => {
    if (!latestForensicPacket) return null;

    const reasons = String(latestForensicPacket.top_trigger_features || "")
      .split("|")
      .map((item) => item.trim())
      .filter(Boolean);

    const confidence = Number(latestForensicPacket.confidence || 0);
    const confidenceBand = confidence >= 95 ? "very high" : confidence >= 90 ? "high" : "medium";
    const confidenceNarrative =
      confidence >= 95
        ? "Model confidence indicates a strong intrusion signature."
        : confidence >= 90
        ? "Model confidence is high and likely reflects suspicious behavior."
        : "Model confidence is moderate; review this flow with context.";

    return {
      reasons,
      confidenceBand,
      confidenceNarrative,
      packetSummary: `${latestForensicPacket.source_ip}:${latestForensicPacket.source_port || 0} -> ${latestForensicPacket.destination_ip}:${latestForensicPacket.destination_port || 0}`,
    };
  }, [latestForensicPacket]);

  const wiredTransfers = useMemo(() => {
    if (!wiredStatus.connected) return [];

    return [...alerts]
      .filter((alert) => {
        const protocol = String(alert.protocol || "").toUpperCase();
        return protocol === "TCP" || protocol === "UDP";
      })
      .slice(-40)
      .reverse()
      .map((alert) => {
        const srcPort = Number(alert.source_port || 0);
        const dstPort = Number(alert.destination_port || 0);
        const detected = srcPort > 0 || dstPort > 0;

        return {
          ...alert,
          detected,
          flowPath: `${alert.source_ip}:${srcPort} -> ${alert.destination_ip}:${dstPort}`,
        };
      });
  }, [alerts, wiredStatus.connected]);

  const chartData = useMemo(() => {
    const bucketSizeSeconds = 5;
    const totalBuckets = 24;
    const bucketSizeMs = bucketSizeSeconds * 1000;
    const now = Date.now();
    const endBucket = Math.floor(now / bucketSizeMs) * bucketSizeMs;
    const startBucket = endBucket - (totalBuckets - 1) * bucketSizeMs;

    const buckets = new Map();
    for (let ts = startBucket; ts <= endBucket; ts += bucketSizeMs) {
      buckets.set(ts, {
        bytes: 0,
        packets: 0,
        attackEvents: 0,
      });
    }

    alerts.forEach((alert) => {
      if (!alert.timestamp) return;
      const eventTime = new Date(alert.timestamp).getTime();
      if (Number.isNaN(eventTime)) return;
      if (eventTime < startBucket || eventTime > endBucket + bucketSizeMs) return;

      const bucketTime = Math.floor(eventTime / bucketSizeMs) * bucketSizeMs;
      const current = buckets.get(bucketTime);
      if (!current) return;

      current.bytes += Number(alert.bytes_in_flow || 0);
      current.packets += Number(alert.packets_in_flow || 0);
      current.attackEvents += 1;
    });

    const data = Array.from(buckets.entries()).map(([timeMs, stats]) => {
      const bytesPerSec = stats.bytes / bucketSizeSeconds;
      const packetsPerSec = stats.packets / bucketSizeSeconds;

      return {
        time: formatLocalTimeLabel(timeMs),
        throughputKbps: Number(((bytesPerSec * 8) / 1000).toFixed(2)),
        packetsPerSec: Number(packetsPerSec.toFixed(2)),
        attackEvents: stats.attackEvents,
      };
    });

    return data.length > 0
      ? data
      : Array.from({ length: 8 }).map((_, index) => ({
          time: formatLocalTimeLabel(now - (7 - index) * 5000),
          throughputKbps: 0,
          packetsPerSec: 0,
          attackEvents: 0,
        }));
  }, [alerts]);

  const addIncomingAlert = (alert) => {
    const key = `${alert.timestamp || ""}-${alert.source_ip}-${alert.destination_ip}-${alert.attack_type}`;

    setAlerts((prev) => {
      const hasAlert = prev.some(
        (a) =>
          `${a.timestamp || ""}-${a.source_ip}-${a.destination_ip}-${a.attack_type}` === key
      );
      if (hasAlert) return prev;
      return [...prev, alert].slice(-300);
    });

    setDisplayedAlerts((prev) => {
      const hasAlert = prev.some(
        (a) =>
          `${a.timestamp || ""}-${a.source_ip}-${a.destination_ip}-${a.attack_type}` === key
      );
      if (hasAlert) return prev;
      return [alert, ...prev].slice(0, 10);
    });

    setDashboardSignal({
      ...alert,
      signal_time: alert.timestamp || new Date().toISOString(),
    });

    if (activeSectionRef.current !== "dashboard") {
      setUnseenDashboardSignals((prev) => Math.min(prev + 1, 99));
    }
  };

  const onAlertSignalToDashboard = (alert) => {
    setDashboardSignal({
      ...alert,
      signal_time: new Date().toISOString(),
    });

    if (activeSectionRef.current !== "dashboard") {
      setUnseenDashboardSignals((prev) => Math.min(prev + 1, 99));
    }
  };

  const changeSection = (section) => {
    setActiveSection(section);
    if (section === "dashboard") {
      setUnseenDashboardSignals(0);
    }
  };

  useEffect(() => {
    activeSectionRef.current = activeSection;
  }, [activeSection]);

  const runTraceback = async (sourceIp, destinationIp, attackType) => {
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
        setActiveSection("traceback");
        return;
      }

      setXaiResult(res.data);
      setActiveSection("traceback");
    } catch (err) {
      console.error(err);
      setXaiError("Traceback failed");
      setActiveSection("traceback");
    }
  };

  useEffect(() => {
    let isMounted = true;

    const fetchInitialData = () => {
      axios
        .get("http://127.0.0.1:8000/attack-summary")
        .then((res) => setSummary(res.data))
        .catch((err) => console.error(err));

      axios
        .get("http://127.0.0.1:8000/alerts")
        .then((res) => {
          const newAlerts = res.data.alerts || [];
          setAlerts(newAlerts.slice(-300));
          setDisplayedAlerts([...newAlerts].reverse().slice(0, 10));

          if (newAlerts.length > 0) {
            const latestAlert = newAlerts[newAlerts.length - 1];
            setDashboardSignal({
              ...latestAlert,
              signal_time: latestAlert.timestamp || new Date().toISOString(),
            });
          }
        })
        .catch((err) => console.error(err));

      axios
        .post("http://127.0.0.1:8000/live/start")
        .catch((err) => console.error("Live capture start failed", err));
    };

    const fetchSummary = () => {
      axios
        .get("http://127.0.0.1:8000/attack-summary")
        .then((res) => setSummary(res.data))
        .catch((err) => console.error(err));

      axios
        .get("http://127.0.0.1:8000/live/status")
        .then((res) => {
          setLiveCaptureStats({
            packets_seen: Number(res.data.packets_seen || 0),
            flows_seen: Number(res.data.flows_seen || 0),
            running: Boolean(res.data.running),
          });
        })
        .catch((err) => console.error(err));

      axios
        .get("http://127.0.0.1:8000/live/wired-status")
        .then((res) => {
          setWiredStatus({
            connected: Boolean(res.data.connected),
            interfaces: res.data.interfaces || [],
            reason: res.data.reason || "unknown",
          });
        })
        .catch((err) => console.error(err));
    };

    const connectLiveSocket = () => {
      if (!isMounted) return;
      connectionSeqRef.current += 1;
      const sequenceId = connectionSeqRef.current;

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }

      if (heartbeatTimerRef.current) {
        clearInterval(heartbeatTimerRef.current);
        heartbeatTimerRef.current = null;
      }

      if (wsRef.current && wsRef.current.readyState <= 1) {
        wsRef.current.close();
      }

      setLiveStatus("Live stream connecting...");
      const socket = new WebSocket("ws://127.0.0.1:8000/ws/live-alerts");
      wsRef.current = socket;

      socket.onopen = () => {
        if (!isMounted || sequenceId !== connectionSeqRef.current) return;
        setLiveStatus("Live stream connected");

        heartbeatTimerRef.current = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send("ping");
          }
        }, 15000);
      };

      socket.onmessage = (event) => {
        if (!isMounted || sequenceId !== connectionSeqRef.current) return;
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "snapshot" && Array.isArray(payload.data)) {
            payload.data
              .slice()
              .reverse()
              .forEach((alert) => addIncomingAlert(alert));
            return;
          }

          if (payload.type === "alert" && payload.data) {
            addIncomingAlert(payload.data);
          }
        } catch (err) {
          console.error("WebSocket parse error", err);
        }
      };

      socket.onerror = () => {
        if (!isMounted || sequenceId !== connectionSeqRef.current) return;
        setLiveStatus("Live stream error");
      };

      socket.onclose = () => {
        if (!isMounted || sequenceId !== connectionSeqRef.current) return;

        if (heartbeatTimerRef.current) {
          clearInterval(heartbeatTimerRef.current);
          heartbeatTimerRef.current = null;
        }

        setLiveStatus("Live stream disconnected, retrying...");
        reconnectTimerRef.current = setTimeout(connectLiveSocket, 3000);
      };
    };

    fetchInitialData();
    fetchSummary();
    connectLiveSocket();
    const interval = setInterval(fetchSummary, 5000);

    return () => {
      isMounted = false;
      clearInterval(interval);

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }

      if (heartbeatTimerRef.current) {
        clearInterval(heartbeatTimerRef.current);
        heartbeatTimerRef.current = null;
      }

      if (wsRef.current && wsRef.current.readyState <= 1) {
        wsRef.current.close();
      }
    };
  }, []);

  return (
    <div className="app-container">
      <div className="sidebar">
        <h2>🛡️ TraceGuard</h2>
        <p className="slogan">Advanced Intelligence • Proven Evidence</p>

        <button
          className={`sidebar-item ${
            activeSection === "dashboard" ? "active" : ""
          }`}
          onClick={() => changeSection("dashboard")}
          type="button"
        >
          <span className="sidebar-item-with-badge">
            Dashboard
            {unseenDashboardSignals > 0 && (
              <span className="sidebar-badge">{unseenDashboardSignals}</span>
            )}
          </span>
        </button>

        <button
          className={`sidebar-item ${
            activeSection === "alerts" ? "active" : ""
          }`}
          onClick={() => changeSection("alerts")}
          type="button"
        >
          Alerts
        </button>

        <button
          className={`sidebar-item ${
            activeSection === "topology" ? "active" : ""
          }`}
          onClick={() => changeSection("topology")}
          type="button"
        >
          Topology
        </button>

        <button
          className={`sidebar-item ${
            activeSection === "wired-transfer" ? "active" : ""
          }`}
          onClick={() => changeSection("wired-transfer")}
          type="button"
        >
          Wired Transfer
        </button>

        <button
          className={`sidebar-item ${
            activeSection === "traceback" ? "active" : ""
          }`}
          onClick={() => changeSection("traceback")}
          type="button"
        >
          Traceback
        </button>
      </div>

      <div className="main">
        <div className="topbar">
          <input className="search" placeholder="Enter IP, Domain..." />
          <div className="status">● {liveStatus}</div>
        </div>

        {activeSection === "dashboard" && (
          <>
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

            <div className="card dashboard-signal-card" style={{ marginTop: "20px" }}>
              <div className="dashboard-signal-header">
                <h3>Dashboard Intrusion Signal</h3>
                {dashboardSignal?.attack_type && (
                  <span className="dashboard-signal-type">{dashboardSignal.attack_type}</span>
                )}
              </div>

              {dashboardSignal ? (
                <>
                  <p className="dashboard-signal-main">
                    Packet: {dashboardSignal.source_ip}:{dashboardSignal.source_port || 0} -&gt; {dashboardSignal.destination_ip}:{dashboardSignal.destination_port || 0}
                  </p>
                  <p className="dashboard-signal-meta">
                    Intrusion Type: {dashboardSignal.attack_type || "Unknown"} | Protocol: {dashboardSignal.protocol || "N/A"} | Confidence: {dashboardSignal.confidence || 0}%
                  </p>
                  <p className="dashboard-signal-meta">
                    Flow Packets: {dashboardSignal.packets_in_flow || 0} | Flow Bytes: {dashboardSignal.bytes_in_flow || 0}
                  </p>
                  <p className="dashboard-signal-time">
                    Signal Time: {new Date(dashboardSignal.signal_time).toLocaleString()}
                  </p>
                </>
              ) : (
                <p className="dashboard-signal-meta">No intrusion signal yet. Open Alerts to inspect and signal one to dashboard.</p>
              )}
            </div>

            <div className="card packet-forensics-card" style={{ marginTop: "20px" }}>
              <div className="packet-forensics-header">
                <h3>Live Packet Forensics</h3>
                <span className={`packet-capture-badge ${liveCaptureStats.running ? "active" : "inactive"}`}>
                  {liveCaptureStats.running ? "Capture Active" : "Capture Offline"}
                </span>
              </div>

              <p className="packet-forensics-stats">
                Packets Observed: {liveCaptureStats.packets_seen} | Flows Tracked: {liveCaptureStats.flows_seen}
              </p>

              {latestForensicPacket && packetForensics ? (
                <>
                  <p className="packet-forensics-main">
                    Flagged Packet Flow: {packetForensics.packetSummary}
                  </p>
                  <p className="packet-forensics-meta">
                    Intrusion Type: {latestForensicPacket.attack_type} | Protocol: {latestForensicPacket.protocol} | Confidence: {latestForensicPacket.confidence}% ({packetForensics.confidenceBand})
                  </p>
                  <p className="packet-forensics-meta">
                    Flow Evidence: {latestForensicPacket.packets_in_flow || 0} packets, {latestForensicPacket.bytes_in_flow || 0} bytes
                  </p>
                  <p className="packet-forensics-explanation">{packetForensics.confidenceNarrative}</p>

                  <div className="packet-forensics-reasons-wrap">
                    <p className="packet-forensics-reasons-title">XAI Forensic Reasons</p>
                    {packetForensics.reasons.length > 0 ? (
                      <div className="packet-forensics-reasons">
                        {packetForensics.reasons.map((reason) => (
                          <span key={reason} className="packet-forensics-pill">{reason}</span>
                        ))}
                      </div>
                    ) : (
                      <p className="packet-forensics-meta">No XAI reasons available yet for this packet.</p>
                    )}
                  </div>
                </>
              ) : (
                <p className="packet-forensics-meta">Live intrusion packets will appear here as soon as detection starts.</p>
              )}
            </div>

            <div className="card" style={{ marginTop: "20px" }}>
              <h3>Network Throughput (Live)</h3>
              <ResponsiveContainer width="100%" height={250}>
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="throughputFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.45} />
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.03} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#23324a" />
                  <XAxis dataKey="time" stroke="#94a3b8" />
                  <YAxis yAxisId="left" stroke="#67e8f9" width={64} />
                  <YAxis yAxisId="right" orientation="right" stroke="#facc15" width={64} />
                  <Tooltip
                    contentStyle={{
                      background: "#0f172a",
                      border: "1px solid #1e293b",
                      borderRadius: "10px",
                    }}
                  />
                  <Legend />
                  <Area
                    yAxisId="left"
                    type="monotone"
                    dataKey="throughputKbps"
                    stroke="#22d3ee"
                    fill="url(#throughputFill)"
                    strokeWidth={2.5}
                    name="Throughput (Kbps)"
                  />
                  <Line
                    type="monotone"
                    yAxisId="right"
                    dataKey="packetsPerSec"
                    stroke="#facc15"
                    strokeWidth={2}
                    dot={false}
                    name="Packets/s"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <AttackGraph alerts={alerts} />
            <GroupedAttack />
            <AttackTimeline alerts={alerts} />
            <AttackerProfiles />
          </>
        )}

        {activeSection === "alerts" && (
          <AlertStream
            alerts={displayedAlerts}
            runTraceback={runTraceback}
            onSignalDashboard={onAlertSignalToDashboard}
          />
        )}

        {activeSection === "topology" && (
          <div className="card" style={{ marginTop: "20px" }}>
            <h3>Network Topology</h3>
            <p>Topology view coming next.</p>
            <AttackGraph alerts={alerts} />
          </div>
        )}

        {activeSection === "wired-transfer" && (
          <div className="card" style={{ marginTop: "20px" }}>
            <h3>Wired Packet Transfer Detection</h3>
            <p className="wired-transfer-subtext">
              Only active when a physical wired interface is connected.
            </p>

            <p className="wired-transfer-subtext">
              Wired Link: {wiredStatus.connected ? "Connected" : "Not Connected"}
              {wiredStatus.connected && wiredStatus.interfaces.length > 0
                ? ` (${wiredStatus.interfaces.join(", ")})`
                : ""}
            </p>

            {!wiredStatus.connected ? (
              <p className="wired-transfer-subtext">
                No physical wired medium detected. This section stays empty until cable/router link is active.
              </p>
            ) : wiredTransfers.length === 0 ? (
              <p className="wired-transfer-subtext">Wired link is active, but no wired packet transfers detected yet.</p>
            ) : (
              <div className="wired-transfer-grid">
                {wiredTransfers.slice(0, 16).map((packet, index) => (
                  <article key={`${packet.timestamp || ""}-${packet.source_ip}-${index}`} className="wired-transfer-card">
                    <div className="wired-transfer-head">
                      <strong>{packet.protocol}</strong>
                      <span className={`wired-status ${packet.detected ? "detected" : "undetected"}`}>
                        {packet.detected ? "Detected" : "Undetected"}
                      </span>
                    </div>
                    <p className="wired-path">{packet.flowPath}</p>
                    <p className="wired-meta">Type: {packet.attack_type}</p>
                    <p className="wired-meta">Confidence: {packet.confidence}%</p>
                    <p className="wired-meta">
                      Flow: {packet.packets_in_flow || 0} packets, {packet.bytes_in_flow || 0} bytes
                    </p>
                    <p className="wired-time">
                      {packet.timestamp ? new Date(packet.timestamp).toLocaleString() : "Time unavailable"}
                    </p>
                  </article>
                ))}
              </div>
            )}
          </div>
        )}

        {activeSection === "traceback" && (
          <div className="card" style={{ marginTop: "20px" }}>
            <h3>Traceback / XAI Result</h3>

            {xaiError && <p>{xaiError}</p>}

            {xaiResult ? (
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
                    <XAIChart features={xaiResult.top_features} />
                  </div>
                )}
              </div>
            ) : (
              <p>Click an alert in the Alerts section to inspect traceback details.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;