import { useEffect, useRef } from "react";

function AttackGraph({ alerts = [] }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    let animationId;
    let offset = 0;

    const width = canvas.width;
    const height = canvas.height;

    const sourceIps = [...new Set(alerts.map((a) => a.source_ip))];
    const destIps = [...new Set(alerts.map((a) => a.destination_ip))];

    const sourceNodes = sourceIps.map((ip, i) => ({
      id: ip,
      label: ip,
      x: 100,
      y: 70 + i * 80,
      type: "source",
    }));

    const destNodes = destIps.map((ip, i) => ({
      id: ip,
      label: ip,
      x: width - 140,
      y: 70 + i * 80,
      type: "dest",
    }));

    const allNodes = [...sourceNodes, ...destNodes];

    const getNodeById = (id) => allNodes.find((n) => n.id === id);

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      // background dots
      ctx.fillStyle = "#1e293b";
      for (let x = 0; x < width; x += 25) {
        for (let y = 0; y < height; y += 25) {
          ctx.fillRect(x, y, 1.5, 1.5);
        }
      }

      // edges from real alerts
      alerts.forEach((alert) => {
        const src = getNodeById(alert.source_ip);
        const dst = getNodeById(alert.destination_ip);
        if (!src || !dst) return;

        let color = "#3b82f6";
        if (alert.confidence >= 95) color = "#ef4444";
        else if (alert.confidence >= 90) color = "#f59e0b";
        else if (alert.confidence >= 80) color = "#38bdf8";
        else color = "#22c55e";

        ctx.beginPath();
        ctx.setLineDash([6, 6]);
        ctx.lineDashOffset = -offset;
        ctx.moveTo(src.x, src.y);
        ctx.bezierCurveTo(
          width / 2 - 80,
          src.y,
          width / 2 + 80,
          dst.y,
          dst.x,
          dst.y
        );
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();
      });

      ctx.setLineDash([]);

      // nodes
      allNodes.forEach((node) => {
        ctx.beginPath();
        ctx.arc(node.x, node.y, 6, 0, Math.PI * 2);
        ctx.fillStyle = node.type === "source" ? "#22c55e" : "#38bdf8";
        ctx.fill();

        ctx.fillStyle = "#e5e7eb";
        ctx.font = "12px Arial";
        ctx.fillText(
          node.label,
          node.type === "source" ? node.x + 12 : node.x - 95,
          node.y + 4
        );
      });

      offset += 1;
      animationId = requestAnimationFrame(draw);
    };

    draw();

    return () => cancelAnimationFrame(animationId);
  }, [alerts]);

  return (
    <div className="card" style={{ marginTop: "20px" }}>
      <h3>Attack Flow Visualization</h3>
      <canvas ref={canvasRef} width={900} height={320}></canvas>
    </div>
  );
}

export default AttackGraph;