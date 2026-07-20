import type { DeviceStatus } from "./types";

// status -> Tailwind class bundle + animation (drives every status pill / tab glow)
export interface StatusMeta {
  label: string;
  text: string;
  bg: string;
  border: string;
  dot: string;
  ring: string; // animation class for the device tab block
  hex: string;
}

export const STATUS: Record<DeviceStatus, StatusMeta> = {
  clean: {
    label: "Clean",
    text: "text-clean",
    bg: "bg-clean-soft",
    border: "border-clean",
    dot: "bg-clean",
    ring: "anim-breathe-green",
    hex: "#16A34A",
  },
  warming: {
    label: "Warming",
    text: "text-warming",
    bg: "bg-warming-soft",
    border: "border-warming",
    dot: "bg-warming",
    ring: "anim-pulse-amber",
    hex: "#CA8A04",
  },
  elevated: {
    label: "Elevated",
    text: "text-elevated",
    bg: "bg-elevated-soft",
    border: "border-elevated",
    dot: "bg-elevated",
    ring: "anim-pulse-amber",
    hex: "#EA580C",
  },
  attack: {
    label: "Attack",
    text: "text-attack",
    bg: "bg-attack-soft",
    border: "border-attack",
    dot: "bg-attack",
    ring: "anim-pulse-red",
    hex: "#DC2626",
  },
  offline: {
    label: "Offline",
    text: "text-ink-muted",
    bg: "bg-surface-2",
    border: "border-line",
    dot: "bg-ink-muted",
    ring: "",
    hex: "#94A3B8",
  },
};

export const statusMeta = (s: DeviceStatus): StatusMeta => STATUS[s] ?? STATUS.clean;

export function fmtSignedPct(frac: number): string {
  const v = Math.round(frac * 100);
  return `${v >= 0 ? "+" : ""}${v}%`;
}

export function fmtNum(n: number, digits = 0): string {
  if (!Number.isFinite(n)) return "—";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function deviationFrac(current: number, base: number): number {
  if (!base || !Number.isFinite(base)) return 0;
  return (current - base) / base;
}

// classnames helper
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
