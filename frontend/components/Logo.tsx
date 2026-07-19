"use client";
import { useEffect, useRef } from "react";

export function PurpleGridLogo({ size = 32, animated = false }: { size?: number; animated?: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const s = size * window.devicePixelRatio;
    canvas.width = s;
    canvas.height = s;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    let frame = 0;
    let rafId: number;
    const draw = () => {
      ctx.clearRect(0, 0, s, s);
      const cx = s / 2, cy = s / 2, r = s * 0.42;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      const outerGrad = ctx.createLinearGradient(0, 0, s, s);
      outerGrad.addColorStop(0, "#7C3AED");
      outerGrad.addColorStop(1, "#4F46E5");
      ctx.strokeStyle = outerGrad;
      ctx.lineWidth = s * 0.04;
      ctx.stroke();
      if (animated) {
        ctx.beginPath();
        const angle = (frame * 0.04) % (Math.PI * 2);
        ctx.arc(cx, cy, r, angle, angle + Math.PI * 0.7);
        ctx.strokeStyle = "#A78BFA";
        ctx.lineWidth = s * 0.04;
        ctx.lineCap = "round";
        ctx.stroke();
      }
      const gridSize = s * 0.52;
      const gridStart = (s - gridSize) / 2;
      const cellSize = gridSize / 3;
      ctx.strokeStyle = "rgba(124, 58, 237, 0.3)";
      ctx.lineWidth = s * 0.018;
      ctx.lineCap = "square";
      for (let i = 0; i <= 3; i++) {
        ctx.beginPath();
        ctx.moveTo(gridStart + i * cellSize, gridStart);
        ctx.lineTo(gridStart + i * cellSize, gridStart + gridSize);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(gridStart, gridStart + i * cellSize);
        ctx.lineTo(gridStart + gridSize, gridStart + i * cellSize);
        ctx.stroke();
      }
      const cells = [[0, 0], [2, 1], [1, 2]];
      cells.forEach(([col, row], idx) => {
        const pulse = animated ? Math.sin(frame * 0.08 + idx * 2) * 0.3 + 0.7 : 1;
        const cellGrad = ctx.createRadialGradient(
          gridStart + col * cellSize + cellSize / 2, gridStart + row * cellSize + cellSize / 2, 0,
          gridStart + col * cellSize + cellSize / 2, gridStart + row * cellSize + cellSize / 2, cellSize * 0.5
        );
        cellGrad.addColorStop(0, `rgba(167, 139, 250, ${0.4 * pulse})`);
        cellGrad.addColorStop(1, `rgba(124, 58, 237, ${0.05 * pulse})`);
        ctx.fillStyle = cellGrad;
        ctx.fillRect(gridStart + col * cellSize + s * 0.012, gridStart + row * cellSize + s * 0.012, cellSize - s * 0.024, cellSize - s * 0.024);
      });
      ctx.beginPath();
      ctx.arc(cx, cy, s * 0.06, 0, Math.PI * 2);
      const dotGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, s * 0.06);
      dotGrad.addColorStop(0, "#C4B5FD");
      dotGrad.addColorStop(1, "#7C3AED");
      ctx.fillStyle = dotGrad;
      ctx.fill();
      frame++;
      if (animated) rafId = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(rafId);
  }, [size, animated]);

  return <canvas ref={canvasRef} style={{ display: "block" }} />;
}

export function LogoWordmark({ size = 32 }: { size?: number }) {
  return (
    <div className="flex items-center gap-3">
      <PurpleGridLogo size={size} />
      <div className="flex flex-col leading-none">
        <span style={{ fontFamily: "'Inter', sans-serif", fontWeight: 700, fontSize: size * 0.5, letterSpacing: "-0.02em", color: "#F0F0FF" }}>
          purple<span style={{ color: "#7C3AED" }}>grid</span>
        </span>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 400, fontSize: size * 0.28, color: "#475569", letterSpacing: "0.08em", textTransform: "uppercase" as const }}>
          security scanner
        </span>
      </div>
    </div>
  );
}
