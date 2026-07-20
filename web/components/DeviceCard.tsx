"use client";

import Link from "next/link";
import VideoPanel from "@/components/VideoPanel";
import { Sparkline } from "@/components/charts";
import { StatusPill, Chip } from "@/components/ui";
import { useDeviceHistory } from "@/lib/api";
import { statusMeta, cx, fmtNum } from "@/lib/format";
import type { Device } from "@/lib/types";

export default function DeviceCard({ device }: { device: Device }) {
  const meta = statusMeta(device.status);
  const samples = useDeviceHistory(device);
  const isAttack = device.status === "attack";

  return (
    <Link
      href={"/device/" + device.id}
      className={cx(
        "block rounded-2xl bg-surface border border-line shadow-card overflow-hidden border-l-4 transition hover:shadow-pop",
        meta.border
      )}
    >
      {device.kind === "camera" ? (
        <VideoPanel
          status={device.status}
          label={device.id}
          model={device.model}
          autoOn={device.id === "esp32-cam-01"}
        />
      ) : (
        <div className="flex h-28 items-center justify-center bg-ink text-ink-muted">
          <span className="font-mono text-[11px] uppercase tracking-widest">
            {device.model}
          </span>
        </div>
      )}

      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="font-semibold text-ink truncate">{device.id}</div>
            <div className="text-[11px] text-ink-muted truncate">
              {device.model + " - " + device.owner}
            </div>
          </div>
          <StatusPill status={device.status} />
        </div>

        <div className="mt-3 h-9">
          <Sparkline data={samples.map((s) => s.cpu)} color={meta.hex} height={36} />
        </div>

        <div
          className={cx(
            "mt-3 font-mono text-[11px]",
            isAttack ? "text-attack" : "text-ink-2"
          )}
        >
          {"cpu " +
            fmtNum(device.metrics.cpu_percent, 0) +
            "% - " +
            fmtNum(device.metrics.packet_rate, 0) +
            "/s - " +
            device.metrics.connection_count +
            " conn"}
        </div>

        <div className="mt-3">
          <Chip>
            {"Sol " +
              device.solution_track +
              (device.solution_track === 1 ? " - OTA" : " - Firewall")}
          </Chip>
        </div>
      </div>
    </Link>
  );
}
