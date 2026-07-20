"use client";

import Link from "next/link";
import { useDevices, useAesState } from "@/lib/api";
import DeviceCard from "@/components/DeviceCard";
import {
  Kpi,
  LiveDot,
  DemoBadge,
  EmptyState,
  Card,
  SectionTitle,
} from "@/components/ui";

export default function OverviewPage() {
  const { devices, live, demo } = useDevices();
  const state = useAesState();

  const deviceCount = devices.length;
  const openCount =
    state?.incidents.filter(
      (i) => i.status === "OPEN" || i.status === "MANUAL_REVIEW"
    ).length ?? 0;

  return (
    <div className="px-8 py-7 max-w-[1500px] mx-auto space-y-8">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold">Fleet overview</h1>
          <p className="text-[13px] text-ink-2">
            Devices stay listed once seen — they're marked Offline if they stop sending signals.
          </p>
        </div>
        <div className="flex gap-3 items-center">
          <LiveDot live={live} />
          {demo ? <DemoBadge /> : null}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 max-w-md">
        <Kpi label="Devices" value={deviceCount} accent="info" />
        <Kpi label="Open incidents" value={openCount} accent="attack" />
      </div>

      <div className="space-y-4">
        <SectionTitle>Devices</SectionTitle>
        {devices.length === 0 ? (
          <EmptyState
            title="No connected devices"
            hint="Start the pipeline or telemetry_sim so devices send signals - they appear here automatically."
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {devices.map((d) => (
              <DeviceCard key={d.id} device={d} />
            ))}
          </div>
        )}
      </div>

      <div className="space-y-4">
        <SectionTitle accent="warming">Recent activity</SectionTitle>
        <Card>
          {state && state.incidents.length ? (
            <div className="font-mono text-[12px] space-y-1">
              {state.incidents.map((i) => (
                <div
                  key={i.incident_id}
                  className="flex items-center gap-3"
                >
                  <span className="text-ink-muted">{i.timestamp}</span>
                  <Link
                    href={"/device/" + i.device_id}
                    className="font-semibold"
                  >
                    {i.device_id}
                  </Link>
                  <span className="text-ink-2 truncate">{i.reason}</span>
                  <span
                    className={
                      "ml-auto " +
                      (i.status === "RESOLVED"
                        ? "text-clean"
                        : i.status === "MANUAL_REVIEW"
                        ? "text-elevated"
                        : i.status === "FAILED"
                        ? "text-attack"
                        : "text-warming")
                    }
                  >
                    {i.status}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No incidents yet" />
          )}
        </Card>
      </div>
    </div>
  );
}
