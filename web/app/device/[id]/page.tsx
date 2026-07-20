"use client";

import Link from "next/link";
import { useState } from "react";
import { useDevice, useDeviceHistory, useAesState, runDemoAttack, runDemoReset } from "@/lib/api";
import VideoPanel from "@/components/VideoPanel";
import IncidentTheater from "@/components/IncidentTheater";
import RemediationTheater from "@/components/RemediationTheater";
import { SignalScope, Gauge } from "@/components/charts";
import {
  Card,
  StatusPill,
  LiveDot,
  DemoBadge,
  EmptyState,
  SectionTitle,
} from "@/components/ui";
import { deviationFrac, fmtSignedPct, fmtNum, cx } from "@/lib/format";

export default function DevicePage({ params }: { params: { id: string } }) {
  const { device, live, demo } = useDevice(params.id);
  const samples = useDeviceHistory(device);
  const state = useAesState();
  const incident = state?.incidents.find((i) => i.device_id === params.id);

  if (!device) {
    return (
      <div className="px-8 py-7">
        <EmptyState
          title="Unknown device"
          hint="No telemetry has ever been recorded for this device ID."
          icon="🔌"
        />
        <div className="mt-4">
          <Link
            href="/"
            className="text-[13px] font-medium text-info hover:underline"
          >
            Back to overview
          </Link>
        </div>
      </div>
    );
  }

  const isCamera = device.kind === "camera";

  const tiles: {
    key: string;
    label: string;
    value: number;
    baseline: number;
    digits?: number;
  }[] = [
    {
      key: "cpu",
      label: "cpu %",
      value: device.metrics.cpu_percent,
      baseline: device.baseline.cpu_percent,
      digits: 0,
    },
    {
      key: "mem",
      label: "memory %",
      value: device.metrics.memory_percent,
      baseline: device.baseline.memory_percent,
      digits: 0,
    },
    {
      key: "packet",
      label: "packet rate /s",
      value: device.metrics.packet_rate,
      baseline: device.baseline.packet_rate,
      digits: 0,
    },
    {
      key: "conn",
      label: "connections",
      value: device.metrics.connection_count,
      baseline: device.baseline.connection_count,
      digits: 0,
    },
  ];

  return (
    <div className="px-8 py-7 max-w-[1400px] mx-auto space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-mono font-semibold text-ink">
            {device.id}
          </h1>
          <p className="text-[12px] text-ink-2">
            {device.model + " - " + device.owner + " - Sol " + device.solution_track + " - firmware " + device.firmware}
          </p>
        </div>
        <div className="flex gap-3 items-center">
          <StatusPill status={device.status} />
          <LiveDot live={live} />
          {demo ? <DemoBadge /> : null}
        </div>
      </div>

      {device.id === "esp32-cam-01" ? (
        <DemoControls status={device.status} />
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {isCamera ? (
          <div className="lg:col-span-5">
            <Card
              title="Camera feed"
              accent={device.status === "attack" ? "attack" : "data"}
            >
              <VideoPanel
                big
                status={device.status}
                label={device.id}
                model={device.model}
                autoOn={device.id === "esp32-cam-01"}
              />
            </Card>
          </div>
        ) : null}

        <div className={isCamera ? "lg:col-span-7" : "lg:col-span-12"}>
          <Card title="Live metrics">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {tiles.map((tile) => {
                const dev = deviationFrac(tile.value, tile.baseline);
                const hot = dev > 0.3;
                const useGauge = tile.key === "cpu" || tile.key === "mem";
                return (
                  <div
                    key={tile.key}
                    className="rounded-2xl border border-line bg-surface-2 p-4 flex flex-col gap-2"
                  >
                    <div className="text-[11px] uppercase tracking-wide text-ink-muted">
                      {tile.label}
                    </div>
                    {useGauge ? (
                      <Gauge
                        value={tile.value}
                        max={100}
                        label=""
                        color={hot ? "var(--attack)" : undefined}
                        size={96}
                      />
                    ) : (
                      <div
                        className={cx(
                          "font-mono text-2xl",
                          hot ? "text-attack" : "text-ink"
                        )}
                      >
                        {fmtNum(tile.value, tile.digits)}
                      </div>
                    )}
                    <div
                      className={cx(
                        "font-mono text-[12px]",
                        hot ? "text-attack" : "text-ink-2"
                      )}
                    >
                      {fmtSignedPct(dev)}
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      </div>

      <Card title="Signal - normal vs under attack" accent="data">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <SignalScope
            samples={samples}
            baseline={device.baseline.cpu_percent}
            metric="cpu"
            label="cpu %"
          />
          <SignalScope
            samples={samples}
            baseline={device.baseline.packet_rate}
            metric="packet"
            label="packet rate /s"
          />
          <SignalScope
            samples={samples}
            baseline={device.baseline.connection_count}
            metric="conn"
            label="connections"
          />
        </div>
        <div className="mt-4 flex items-center gap-4 text-[12px] text-ink-2">
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2 w-3 rounded-full bg-clean" />
            green = normal baseline
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2 w-3 rounded-full bg-attack" />
            red = under attack
          </span>
        </div>
      </Card>

      <IncidentTheater device={device} incident={incident} />

      <RemediationTheater device={device} incident={incident} />
    </div>
  );
}

// One-click attack→auto-patch story for the cam-01 demo. The buttons only flip a
// server-side control file (POST /api/demo/cam01/*); scripts/live_demo.py walks the
// device through the real fleet_status.json + incident artifacts, and the polled
// views above animate the rest. "Reset" returns everything to the clean baseline.
function DemoControls({ status }: { status: string }) {
  const [busy, setBusy] = useState<null | "attack" | "reset">(null);
  const underAttack = status === "attack" || status === "elevated" || status === "warming";

  async function fire(kind: "attack" | "reset") {
    setBusy(kind);
    try {
      await (kind === "attack" ? runDemoAttack() : runDemoReset());
    } catch {
      /* the polled views will reflect whatever the backend recorded */
    } finally {
      setTimeout(() => setBusy(null), 800);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-line bg-surface-2 px-5 py-4">
      <div className="mr-auto">
        <div className="text-[13px] font-semibold text-ink">Live demo · esp32-cam-01</div>
        <div className="text-[11px] text-ink-muted">
          Send the attack file → watch detect, patch, and self-heal. Reset returns to baseline.
        </div>
      </div>
      <button
        onClick={() => fire("attack")}
        disabled={busy !== null}
        className="rounded-xl bg-attack px-4 py-2 text-[13px] font-semibold text-white shadow-sm transition hover:opacity-90 disabled:opacity-50"
      >
        {busy === "attack" ? "Sending attack…" : "▶ Send attack file"}
      </button>
      <button
        onClick={() => fire("reset")}
        disabled={busy !== null}
        className="rounded-xl border border-line bg-surface px-4 py-2 text-[13px] font-semibold text-ink transition hover:bg-surface-2 disabled:opacity-50"
      >
        {busy === "reset" ? "Resetting…" : "↺ Reset"}
      </button>
      <span
        className={
          "ml-1 inline-flex items-center gap-1.5 text-[11px] font-medium " +
          (underAttack ? "text-attack" : "text-clean")
        }
      >
        <span className={"h-2 w-2 rounded-full " + (underAttack ? "bg-attack" : "bg-clean")} />
        {underAttack ? "under attack — patching" : "nominal"}
      </span>
    </div>
  );
}
