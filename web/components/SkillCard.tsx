"use client";

import { Card, Chip } from "@/components/ui";
import { Gauge } from "@/components/charts";
import { cx } from "@/lib/format";
import type { Skill } from "@/lib/types";

export default function SkillCard({
  skill,
  onApprove,
  onReject,
  busy,
}: {
  skill: Skill;
  onApprove?: () => void;
  onReject?: () => void;
  busy?: boolean;
}) {
  const bench = skill.benchmark;
  const detection = Math.round((bench?.detection_rate ?? 0) * 100);
  const falsePositive = Math.round((bench?.false_positive_rate ?? 0) * 100);

  return (
    <Card accent="ai">
      <div className="flex items-center justify-between gap-3">
        <span className="font-mono font-semibold text-ink">{skill.skill_id}</span>
        <Chip>{skill.status}</Chip>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-2 text-[12px] text-ink-2">
        {skill.cve_id ? <Chip tone="info">{skill.cve_id}</Chip> : null}
        {skill.device_type ? <span>{skill.device_type}</span> : null}
        <span>
          deviation_threshold 0.50 -&gt;{" "}
          <span className="text-clean font-semibold">
            {skill.params.deviation_threshold ?? "-"}
          </span>
        </span>
      </div>

      <div className="mt-4 flex gap-6">
        <Gauge
          value={detection}
          label="detection rate"
          sublabel="min 80%"
          color="#16A34A"
        />
        <Gauge
          value={falsePositive}
          label="false positive"
          sublabel="max 10%"
          color="#0891B2"
        />
      </div>

      <div className="mt-3 font-mono text-[11px] text-ink-muted">
        {(bench?.sample_size ?? 0) + " attack samples - " +
          (bench?.normal_sample_size ?? 0) + " normal - " +
          (bench?.latency_ms ?? 0) + "ms"}
      </div>

      <div className="mt-4 flex gap-3">
        <button
          type="button"
          onClick={onApprove}
          disabled={busy}
          className={cx(
            "bg-clean text-white rounded-lg px-4 py-2 text-sm font-semibold",
            busy && "opacity-60",
          )}
        >
          {busy ? "Deploying..." : "Approve & deploy"}
        </button>
        <button
          type="button"
          onClick={onReject}
          disabled={busy}
          className={cx(
            "border border-line text-ink-2 rounded-lg px-4 py-2 text-sm",
            busy && "opacity-60",
          )}
        >
          Reject
        </button>
      </div>
    </Card>
  );
}
