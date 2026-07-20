"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Sample, ThresholdPoint } from "@/lib/types";
import { cx } from "@/lib/format";

// ─── tiny inline sparkline (no recharts; cheap, runs in every device tile) ─────
export function Sparkline({ data, color = "#0891B2", height = 34 }: { data: number[]; color?: string; height?: number }) {
  if (!data.length) return <svg style={{ height }} className="w-full" />;
  const w = 300;
  const h = height;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const span = max - min || 1;
  const pts = data
    .map((v, i) => `${(i / Math.max(1, data.length - 1)) * w},${h - ((v - min) / span) * (h - 4) - 2}`)
    .join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="w-full" style={{ height }}>
      <polyline fill="none" stroke={color} strokeWidth={1.8} points={pts} />
    </svg>
  );
}

// ─── normal-vs-attack signal scope (green normal baseline + live line) ─────────
export function SignalScope({
  samples,
  baseline,
  metric,
  label,
  height = 150,
}: {
  samples: Sample[];
  baseline: number;
  metric: "cpu" | "packet" | "conn" | "mem";
  label: string;
  height?: number;
}) {
  const data = samples.map((s) => ({ t: s.t, v: s[metric] }));
  const last = data.length ? data[data.length - 1].v : 0;
  const breaching = last > baseline * 1.3;
  const color = breaching ? "#DC2626" : "#16A34A";
  const dev = baseline ? Math.round(((last - baseline) / baseline) * 100) : 0;
  const gid = `scope-${metric}`;
  return (
    <div>
      <div className="flex items-baseline justify-between mb-1">
        <span className="font-mono text-[11px] uppercase tracking-wide text-ink-2">{label}</span>
        <span className={cx("font-mono text-[12px] font-semibold", breaching ? "text-attack" : "text-clean")}>
          {dev >= 0 ? "+" : ""}
          {dev}%
        </span>
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: -4 }}>
          <defs>
            <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.3} />
              <stop offset="100%" stopColor={color} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#E3E8EF" vertical={false} />
          <XAxis dataKey="t" hide />
          <YAxis tick={{ fontSize: 10, fill: "#94A3B8" }} width={34} domain={[0, "auto"]} />
          <ReferenceLine
            y={baseline}
            stroke="#16A34A"
            strokeDasharray="4 4"
            label={{ value: "normal", fontSize: 10, fill: "#16A34A", position: "insideTopLeft" }}
          />
          <Area type="monotone" dataKey="v" stroke={color} strokeWidth={2.2} fill={`url(#${gid})`} isAnimationActive={false} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ─── SVG arc gauge ─────────────────────────────────────────────────────────────
export function Gauge({
  value,
  max = 100,
  label,
  sublabel,
  color = "#16A34A",
  size = 92,
}: {
  value: number;
  max?: number;
  label: string;
  sublabel?: string;
  color?: string;
  size?: number;
}) {
  const r = size / 2 - 8;
  const c = 2 * Math.PI * r;
  const frac = Math.max(0, Math.min(1, value / max));
  const off = c * (1 - frac);
  const mid = size / 2;
  return (
    <div className="flex items-center gap-4">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={mid} cy={mid} r={r} fill="none" stroke="#E3E8EF" strokeWidth={7} />
        <circle
          cx={mid}
          cy={mid}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={7}
          strokeDasharray={c}
          strokeDashoffset={off}
          strokeLinecap="round"
          transform={`rotate(-90 ${mid} ${mid})`}
        />
      </svg>
      <div>
        <div className="font-mono text-2xl font-semibold" style={{ color }}>
          {Math.round(value)}
          {max === 100 ? "%" : ""}
        </div>
        <div className="text-[11px] uppercase tracking-wide text-ink-muted">{label}</div>
        {sublabel && <div className="text-[11px] text-ink-2">{sublabel}</div>}
      </div>
    </div>
  );
}

// ─── detection-rate-over-deploys line ──────────────────────────────────────────
export function ThresholdChart({ points }: { points: ThresholdPoint[] }) {
  const data = points.map((p) => ({ name: p.label, rate: Math.round((p.detection_rate ?? 0) * 100) }));
  return (
    <ResponsiveContainer width="100%" height={170}>
      <LineChart data={data} margin={{ top: 8, right: 14, bottom: 0, left: 4 }}>
        <CartesianGrid stroke="#E3E8EF" vertical={false} />
        <XAxis dataKey="name" tick={{ fontSize: 10, fill: "#94A3B8" }} />
        <YAxis domain={[70, 100]} tick={{ fontSize: 10, fill: "#94A3B8" }} width={42} tickFormatter={(v) => `${v}%`} />
        <Tooltip
          contentStyle={{ borderRadius: 10, border: "1px solid #E3E8EF", fontSize: 12 }}
          formatter={(v) => [`${v}%`, "detection"]}
        />
        <Line type="monotone" dataKey="rate" stroke="#16A34A" strokeWidth={2.4} dot={{ r: 4, fill: "#16A34A" }} isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

// ─── before/after stealth-attack split ─────────────────────────────────────────
export function BeforeAfter() {
  return (
    <div className="grid grid-cols-2 rounded-xl border border-line overflow-hidden">
      <div className="p-4 border-r border-line">
        <div className="font-mono text-[11px] uppercase tracking-wide text-ink-muted mb-2">Before · threshold 0.50</div>
        <svg viewBox="0 0 240 80" className="w-full">
          <line x1="0" y1="26" x2="240" y2="26" stroke="#94A3B8" strokeDasharray="4 4" />
          <path d="M0,56 L80,54 L120,42 L160,44 L240,43" fill="none" stroke="#DC2626" strokeWidth="1.8" opacity="0.85" />
        </svg>
        <div className="font-mono text-[12px] font-bold text-attack mt-2">verdict: Normal — MISSED</div>
      </div>
      <div className="p-4">
        <div className="font-mono text-[11px] uppercase tracking-wide text-ink-muted mb-2">After · threshold 0.35</div>
        <svg viewBox="0 0 240 80" className="w-full">
          <line x1="0" y1="48" x2="240" y2="48" stroke="#16A34A" strokeDasharray="4 4" />
          <path d="M120,42 L160,44 L240,43 L240,48 L120,48 Z" fill="#16A34A" opacity="0.18" />
          <path d="M0,56 L80,54 L120,42 L160,44 L240,43" fill="none" stroke="#16A34A" strokeWidth="1.8" />
        </svg>
        <div className="font-mono text-[12px] font-bold text-clean mt-2">verdict: 🚨 ANOMALY — CAUGHT</div>
      </div>
    </div>
  );
}

// ─── horizontal deviation bars (per metric, fractional → %) ────────────────────
export function DeviationBars({ deviations }: { deviations: Record<string, number> }) {
  const entries = Object.entries(deviations).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return (
    <div className="space-y-2">
      {entries.map(([k, v]) => (
        <div key={k} className="flex items-center gap-3">
          <span className="font-mono text-[11px] text-ink-2 w-28 shrink-0">{k}</span>
          <div className="flex-1 h-2 rounded-full bg-surface-2 overflow-hidden">
            <div className="h-full rounded-full bg-attack" style={{ width: `${Math.min(100, (v / max) * 100)}%` }} />
          </div>
          <span className="font-mono text-[11px] font-semibold text-attack w-16 text-right">+{Math.round(v * 100)}%</span>
        </div>
      ))}
    </div>
  );
}
