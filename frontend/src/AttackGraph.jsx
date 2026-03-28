import { useEffect, useMemo, useRef, useState } from "react";

function AttackGraph({ alerts = [], flows = [] }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const [canvasSize, setCanvasSize] = useState({ width: 900, height: 360 });

  const graphModel = useMemo(() => {
    const streamSource = flows.length > 0 ? flows : alerts;

    const withTimestamps = streamSource
      .map((alert) => ({
        ...alert,
        parsedTime: alert.timestamp ? new Date(alert.timestamp).getTime() : 0,
      }))
      .sort((a, b) => a.parsedTime - b.parsedTime)
      .slice(-80);

    const sourceCounts = new Map();
    const destinationCounts = new Map();

    withTimestamps.forEach((alert) => {
      sourceCounts.set(
        alert.source_ip,
        (sourceCounts.get(alert.source_ip) || 0) + 1
      );
      destinationCounts.set(
        alert.destination_ip,
        (destinationCounts.get(alert.destination_ip) || 0) + 1
      );
    });

    const sourceIps = Array.from(sourceCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([ip]) => ip);

    const destinationIps = Array.from(destinationCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([ip]) => ip);

    const edges = withTimestamps.filter(
      (alert) =>
        sourceIps.includes(alert.source_ip) &&
        destinationIps.includes(alert.destination_ip)
    );

    return {
      sourceIps,
      destinationIps,
      edges,
      sourceCounts,
      destinationCounts,
    };
  }, [alerts]);

  useEffect(() => {
    const updateSize = () => {
      if (!containerRef.current) return;
      const width = Math.max(680, Math.floor(containerRef.current.clientWidth));
      setCanvasSize({ width, height: 360 });
    };

    updateSize();
    window.addEventListener("resize", updateSize);

    return () => window.removeEventListener("resize", updateSize);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId;
    let offset = 0;

    const pixelRatio = window.devicePixelRatio || 1;
    const width = canvasSize.width;
    const height = canvasSize.height;
    canvas.width = width * pixelRatio;
    canvas.height = height * pixelRatio;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);

    const { sourceIps, destinationIps, edges, sourceCounts, destinationCounts } =
      graphModel;

    const buildVerticalNodes = (ips, xPosition, type) => {
      if (ips.length === 0) return [];

      const usableHeight = height - 80;
      const step = usableHeight / Math.max(ips.length - 1, 1);

      return ips.map((ip, index) => ({
        id: ip,
        label: ip,
        x: xPosition,
        y: 40 + step * index,
        type,
      }));
    };

    const sourceNodes = buildVerticalNodes(sourceIps, 120, "source");
    const destNodes = buildVerticalNodes(destinationIps, width - 120, "dest");
    const allNodes = [...sourceNodes, ...destNodes];

    const getNodeById = (id) => allNodes.find((node) => node.id === id);

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      const bgGradient = ctx.createLinearGradient(0, 0, width, height);
      bgGradient.addColorStop(0, "#0b1220");
      bgGradient.addColorStop(1, "#101b30");
      ctx.fillStyle = bgGradient;
      ctx.fillRect(0, 0, width, height);

      ctx.fillStyle = "rgba(56, 189, 248, 0.15)";
      for (let x = 20; x < width; x += 28) {
        for (let y = 16; y < height; y += 28) {
          ctx.fillRect(x, y, 1.1, 1.1);
        }
      }

      edges.forEach((alert, index) => {
        const src = getNodeById(alert.source_ip);
        const dst = getNodeById(alert.destination_ip);
        if (!src || !dst) return;

        let color = "#3b82f6";
        if (typeof alert.confidence === "number") {
          if (alert.confidence >= 95) color = "#ef4444";
          else if (alert.confidence >= 90) color = "#f59e0b";
          else if (alert.confidence >= 80) color = "#38bdf8";
          else color = "#22c55e";
        } else {
          const protocol = String(alert.protocol || "").toUpperCase();
          if (protocol === "TCP") color = "#22d3ee";
          else if (protocol === "UDP") color = "#60a5fa";
          else color = "#34d399";
        }

        const isRecent = index >= edges.length - 12;
        const widthScale = 1 + Number(alert.confidence || 0) / 60;

        ctx.beginPath();
        ctx.setLineDash([6, 6]);
        ctx.lineDashOffset = -offset;
        ctx.moveTo(src.x, src.y);
        ctx.bezierCurveTo(
          width / 2 - 95,
          src.y,
          width / 2 + 95,
          dst.y,
          dst.x,
          dst.y
        );
        ctx.strokeStyle = color;
        ctx.lineWidth = widthScale;
        ctx.globalAlpha = isRecent ? 0.95 : 0.45;
        ctx.stroke();

        if (isRecent) {
          ctx.beginPath();
          ctx.arc(dst.x, dst.y, 4 + Math.sin(offset / 8) * 1.5, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.globalAlpha = 0.35;
          ctx.fill();
        }
      });

      ctx.setLineDash([]);
      ctx.globalAlpha = 1;

      allNodes.forEach((node) => {
        const nodeCount =
          node.type === "source"
            ? sourceCounts.get(node.id) || 0
            : destinationCounts.get(node.id) || 0;

        ctx.beginPath();
        ctx.arc(node.x, node.y, 8, 0, Math.PI * 2);
        ctx.fillStyle = node.type === "source" ? "#22c55e" : "#38bdf8";
        ctx.fill();

        ctx.beginPath();
        ctx.arc(node.x, node.y, 12, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(203, 213, 225, 0.3)";
        ctx.lineWidth = 1;
        ctx.stroke();

        ctx.fillStyle = "#e5e7eb";
        ctx.font = "12px Inter, sans-serif";
        ctx.fillText(
          node.label,
          node.type === "source" ? node.x + 16 : node.x - 140,
          node.y + 2
        );

        ctx.fillStyle = "#94a3b8";
        ctx.font = "11px Inter, sans-serif";
        ctx.fillText(
          `${nodeCount} flow${nodeCount === 1 ? "" : "s"}`,
          node.type === "source" ? node.x + 16 : node.x - 140,
          node.y + 16
        );
      });

      if (edges.length === 0) {
        ctx.fillStyle = "#94a3b8";
        ctx.font = "14px Inter, sans-serif";
        ctx.fillText("Waiting for live packet flow...", width / 2 - 90, height / 2);
      }

      offset += 1;
      animationId = requestAnimationFrame(draw);
    };

    draw();

    return () => cancelAnimationFrame(animationId);
  }, [graphModel, canvasSize]);

  return (
    <div className="card attack-flow-card" style={{ marginTop: "20px" }} ref={containerRef}>
      <h3>Flow Visualisation</h3>
      <canvas ref={canvasRef}></canvas>
    </div>
  );
}

export default AttackGraph;