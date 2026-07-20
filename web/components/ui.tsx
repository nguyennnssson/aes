import type { ReactNode } from "react";
import type { DeviceStatus } from "@/lib/types";
import { cx, statusMeta } from "@/lib/format";

export type Accent = "clean" | "warming" | "elevated" | "attack" | "info" | "data" | "ai" | "none";

const ACCENT_BAR: Record<Accent, string> = {
  clean: "bg-clean",
  warming: "bg-warming",
  elevated: "bg-elevated",
  attack: "bg-attack",
  info: "bg-info",
  data: "bg-data",
  ai: "bg-ai",
  none: "bg-transparent",
};
const ACCENT_TEXT: Record<Accent, string> = {
  clean: "text-clean",
  warming: "text-warming",
  elevated: "text-elevated",
  attack: "text-attack",
  info: "text-info",
  data: "text-data",
  ai: "text-ai",
  none: "text-ink",
};
const ACCENT_TOP: Record<Accent, string> = {
  clean: "border-t-clean",
  warming: "border-t-warming",
  elevated: "border-t-elevated",
  attack: "border-t-attack",
  info: "border-t-info",
  data: "border-t-data",
  ai: "border-t-ai",
  none: "border-t-line",
};

export function Card({
  title,
  accent = "none",
  right,
  className,
  children,
}: {
  title?: string;
  accent?: Accent;
  right?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  const hasHeader = Boolean(title || right);
  return (
    <section className={cx("rounded-2xl bg-surface border border-line shadow-card", className)}>
      {hasHeader && (
        <header className="flex items-center gap-3 px-5 pt-4 pb-3">
          {accent !== "none" && <span className={cx("h-3.5 w-[3px] rounded-full", ACCENT_BAR[accent])} />}
          {title && (
            <h3 className="text-[12px] font-semibold uppercase tracking-[0.12em] text-ink-2">{title}</h3>
          )}
          {right && <div className="ml-auto">{right}</div>}
        </header>
      )}
      <div className={hasHeader ? "px-5 pb-5" : "p-5"}>{children}</div>
    </section>
  );
}

export function SectionTitle({ children, accent = "data" }: { children: ReactNode; accent?: Accent }) {
  return (
    <h2 className="flex items-center gap-2.5 text-[12px] font-bold uppercase tracking-[0.14em] text-ink-2 mb-3">
      <span className={cx("h-3.5 w-[3px] rounded-full", ACCENT_BAR[accent])} />
      {children}
    </h2>
  );
}

export function StatusPill({ status, size = "md" }: { status: DeviceStatus; size?: "sm" | "md" }) {
  const m = statusMeta(status);
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full border font-semibold uppercase tracking-wide",
        m.bg,
        m.text,
        m.border,
        size === "sm" ? "px-2 py-0.5 text-[9px]" : "px-2.5 py-1 text-[10px]"
      )}
    >
      <span className={cx("h-1.5 w-1.5 rounded-full", m.dot, status === "attack" && "dot-pulse-red")} />
      {m.label}
    </span>
  );
}

export function Kpi({
  label,
  value,
  unit,
  accent = "none",
  hint,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  accent?: Accent;
  hint?: string;
}) {
  return (
    <div className={cx("rounded-xl bg-surface border border-line border-t-2 shadow-card px-4 py-3", ACCENT_TOP[accent])}>
      <div className={cx("font-mono text-2xl font-semibold tracking-tight", ACCENT_TEXT[accent])}>
        {value}
        {unit && <span className="text-base text-ink-muted ml-0.5">{unit}</span>}
      </div>
      <div className="mt-1 text-[11px] uppercase tracking-[0.08em] text-ink-muted">{label}</div>
      {hint && <div className="text-[11px] text-ink-2 mt-0.5">{hint}</div>}
    </div>
  );
}

export function Chip({ children, tone = "line" }: { children: ReactNode; tone?: "line" | "info" | "ai" | "data" }) {
  const map: Record<string, string> = {
    line: "border-line text-ink-2 bg-surface-2",
    info: "border-info text-info bg-info-soft",
    ai: "border-ai text-ai bg-ai-soft",
    data: "border-data text-data bg-data-soft",
  };
  return <span className={cx("inline-block rounded-md border px-2 py-0.5 font-mono text-[10px]", map[tone])}>{children}</span>;
}

export function DemoBadge() {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-warming-soft text-warming border border-warming px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide">
      <span className="h-1.5 w-1.5 rounded-full bg-warming" />
      Demo data
    </span>
  );
}

export function LiveDot({ live }: { live: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-ink-2">
      <span className={cx("h-2 w-2 rounded-full", live ? "bg-clean anim-breathe-green" : "bg-ink-muted")} />
      {live ? "Live" : "Demo"}
    </span>
  );
}

export function EmptyState({ title, hint, icon }: { title: string; hint?: string; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-12 px-6">
      <div className="text-3xl mb-3 opacity-60">{icon ?? "📡"}</div>
      <div className="text-sm font-semibold text-ink">{title}</div>
      {hint && <div className="text-[12px] text-ink-2 mt-1 max-w-sm">{hint}</div>}
    </div>
  );
}
