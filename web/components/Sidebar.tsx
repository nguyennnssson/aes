"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useDevices } from "@/lib/api";
import { StatusPill, LiveDot, DemoBadge } from "@/components/ui";
import { statusMeta, cx } from "@/lib/format";

export default function Sidebar() {
  const { devices, live, demo } = useDevices();
  const pathname = usePathname();

  const overviewActive = pathname === "/";
  const learningActive = pathname === "/learning";

  return (
    <aside className="w-64 shrink-0 bg-surface border-r border-line min-h-screen sticky top-0 self-start flex flex-col">
      {/* Brand */}
      <div className="p-5">
        <div className="flex items-center gap-2.5">
          <span className="h-3 w-3 rounded-full bg-data" />
          <span className="font-bold text-lg text-ink leading-none">AES</span>
        </div>
        <p className="mt-1 text-[11px] text-ink-muted">Autonomous Edge-Sentinel</p>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-3 space-y-1">
        {/* Overview */}
        <Link
          href="/"
          className={cx(
            "flex items-center gap-2 rounded-lg border p-2.5 text-sm font-medium transition-shadow hover:shadow-pop",
            overviewActive
              ? "bg-surface-2 border-line-strong text-ink"
              : "border-line text-ink-2 hover:bg-surface-2"
          )}
        >
          <span aria-hidden>🏠</span>
          <span>Overview</span>
        </Link>

        {/* Devices section */}
        <div className="px-2 pt-4 text-[10px] uppercase tracking-wider text-ink-muted">
          Devices
        </div>

        {devices.map((device) => {
          const meta = statusMeta(device.status);
          const href = "/device/" + device.id;
          const active = pathname === href;
          return (
            <Link
              key={device.id}
              href={href}
              className={cx(
                "block rounded-lg border p-2.5 transition-shadow hover:shadow-pop",
                meta.ring,
                active
                  ? "bg-surface-2 border-line-strong"
                  : "border-line hover:bg-surface-2",
                device.status === "attack" ? "shadow-glow" : ""
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="font-mono text-[13px] font-medium text-ink truncate">
                    {device.id}
                  </div>
                  <div className="text-[10px] text-ink-muted truncate">
                    {device.model}
                  </div>
                </div>
                <StatusPill status={device.status} size="sm" />
              </div>
            </Link>
          );
        })}

        {devices.length === 0 && (
          <div className="px-2 py-3 text-[11px] text-ink-muted">
            No connected devices - waiting for signals...
          </div>
        )}

        {/* Divider + Self-Improvement */}
        <div className="my-3 border-t border-line" />
        <Link
          href="/learning"
          className={cx(
            "flex items-center gap-2 rounded-lg border p-2.5 text-sm font-medium transition-shadow hover:shadow-pop",
            learningActive
              ? "bg-surface-2 border-line-strong text-ink"
              : "border-line text-ink-2 hover:bg-surface-2"
          )}
        >
          <span className="h-2.5 w-2.5 rounded-full bg-ai" />
          <span>Self-Improvement</span>
        </Link>
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-line">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-[12px] text-ink-2">
            <LiveDot live={live} />
            <span className="font-mono">
              {devices.filter((d) => d.connected).length + "/" + devices.length + " connected"}
            </span>
          </div>
          {demo && <DemoBadge />}
        </div>
      </div>
    </aside>
  );
}
