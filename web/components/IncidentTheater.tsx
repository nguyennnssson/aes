"use client";

import { Card, Chip, EmptyState } from "@/components/ui";
import { DeviationBars } from "@/components/charts";
import { cx } from "@/lib/format";
import type { Device, Incident } from "@/lib/types";

type Stage = {
  name: string;
  sub: string;
  state: "done" | "active" | "default" | "optional";
};

// Maps each real pipeline `stage` (written by monitor_agent → monitor_agent_mqtt →
// response_agent) to the index of the bus node that is ACTIVE at that moment, so the
// 7 boxes light up strictly one at a time in pipeline order:
//   0 Device · 1 Monitor · 2 Intel · 3 Hermes · 4 Response · 5 OpenClaw · 6 Discord
const STAGE_ACTIVE_NODE: Record<string, number> = {
  monitor_logged: 2, // Monitor done → Intel running RAG
  intel_done: 3, //     Intel done   → Hermes reasoning
  hermes_done: 4, //    verdict in   → Response routing
  vuln_confirmed: 4, // Response confirmed the vuln, routing to a handler
  // Response handed off → OpenClaw is executing the remediation
  patch_generated: 5,
  patch_failed: 5,
  gate1_running: 5,
  gate1_passed: 5,
  gate1_failed: 5,
  building: 5,
  build_failed: 5,
  flashing: 5,
  flash_failed: 5,
  validating: 5,
  boot_timeout: 5,
  awaiting_flash_approval: 5,
  approved_for_install: 5,
  whitelist_built: 5,
  dry_run: 5,
  awaiting_firewall_enforcement: 5,
  enforced: 5,
  // execution finished → the only thing left is the Discord alert
  boot_confirmed: 6,
  verified: 6,
};

// Builds the 7-box pipeline bus from the incident's real `stage`/`status` fields so
// the bus reflects exactly where the live pipeline is — every node before the active
// one is done, the active one pulses, and the rest stay idle until the signal reaches
// them. On a terminal status every node (including the Discord alert) reads as done.
function buildStages(incident: Incident): Stage[] {
  const stage = incident.stage;
  const terminal = incident.status === "RESOLVED";
  // Where the signal is on the bus right now. Before any stage write, the monitor
  // has only just logged it, so Intel (2) is the first thing spinning up.
  const active = stage && stage in STAGE_ACTIVE_NODE ? STAGE_ACTIVE_NODE[stage] : 2;

  const nodes = [
    { name: "Device", sub: "signal" },
    { name: "Monitor", sub: "EWMA" },
    { name: "Intel", sub: "RAG" },
    { name: "Hermes", sub: "reason" },
    { name: "Response", sub: "route" },
    { name: "OpenClaw", sub: "execute" },
    { name: "Discord", sub: "alert" },
  ];

  return nodes.map((n, i): Stage => {
    let state: Stage["state"];
    if (terminal) state = "done";
    else if (i < active) state = "done";
    else if (i === active) state = "active";
    else state = i === 6 ? "optional" : "default";
    return { ...n, state };
  });
}

function statusLineTone(status: Incident["status"]): string {
  switch (status) {
    case "RESOLVED":
      return "text-clean";
    case "MANUAL_REVIEW":
      return "text-warming";
    case "FAILED":
      return "text-attack";
    default:
      return "text-ink-2";
  }
}

export default function IncidentTheater({
  device,
  incident,
}: {
  device: Device;
  incident?: Incident;
}) {
  if (!incident) {
    return (
      <Card title="Incident theater" accent="clean">
        <EmptyState
          title="No active incident"
          hint="This device is nominal - the detection pipeline is idle."
          icon="🟢"
        />
      </Card>
    );
  }

  const stages = buildStages(incident);
  const verdict = incident.verdict;
  const cveLabel = incident.cve_id
    ? incident.cve_severity || incident.cve_score !== undefined
      ? `${incident.cve_id} · ${incident.cve_severity ?? ""}${
          incident.cve_score !== undefined ? ` ${incident.cve_score}` : ""
        }`.trim()
      : incident.cve_id
    : "no CVE matched";

  const verdictJson = [
    `  "action": ${JSON.stringify(verdict?.action ?? null)},`,
    `  "cve_id": ${JSON.stringify(verdict?.cve_id ?? null)},`,
    `  "confidence": ${
      verdict?.confidence !== undefined ? verdict.confidence : "null"
    },`,
    `  "solution_track": ${
      verdict?.solution_track !== undefined ? verdict.solution_track : "null"
    }`,
  ].join("\n");

  return (
    <Card title="Incident theater" accent="data">
      {/* Pipeline bus */}
      <div className="relative py-8">
        <div className="absolute left-8 right-8 top-1/2 h-0.5 bg-line" />
        <div className="anim-travel absolute top-1/2 -translate-y-1/2 h-2.5 w-2.5 rounded-full bg-data shadow" />
        <div className="relative flex flex-wrap justify-between gap-2">
          {stages.map((stage) => {
            const done = stage.state === "done";
            const active = stage.state === "active";
            const optional = stage.state === "optional";
            return (
              <div
                key={stage.name}
                className={cx(
                  "relative z-10 rounded-lg border bg-surface px-3 py-2 text-center min-w-[92px]",
                  done && "border-clean",
                  active && "border-data ring-2 ring-data/30",
                  optional && "opacity-50 border-dashed",
                  !done && !active && !optional && "border-line"
                )}
              >
                <div
                  className={cx(
                    "font-medium text-xs",
                    active && "text-data"
                  )}
                >
                  {stage.name}
                </div>
                <div className="text-[10px] text-ink-muted">
                  {done ? (
                    <>
                      <span className="text-clean">✓ </span>
                      {stage.sub}
                    </>
                  ) : (
                    stage.sub
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* I/O panel */}
      <div className="rounded-xl bg-surface-2 p-4 space-y-3">
        <div>
          <div className="text-xs font-medium text-ink-2 mb-2">
            Monitor → EWMA deviations
          </div>
          <DeviationBars deviations={incident.deviations} />
        </div>

        <div className="flex items-center gap-2 text-xs text-ink-2">
          <span className="font-medium">Intel → RAG</span>
          <Chip tone="info">{cveLabel}</Chip>
        </div>

        <div>
          <div className="text-xs font-medium text-ink-2 mb-1">
            Hermes verdict
          </div>
          <pre className="font-mono text-xs text-ink-2 whitespace-pre-wrap">
            {`{\n${verdictJson}\n}`}
          </pre>
          {verdict?.reasoning ? (
            <div className="font-mono text-[11px] text-ink-muted mt-1">
              {verdict.reasoning}
            </div>
          ) : null}
        </div>

        <div className="text-xs text-ink-2">
          <span className="font-mono">
            confidence {incident.confidence}
          </span>
          <span className="text-ink-muted"> — {incident.reason}</span>
        </div>

        <div
          className={cx(
            "text-xs font-medium",
            statusLineTone(incident.status)
          )}
        >
          {incident.status}
          {incident.latency_ms !== undefined ? (
            <span className="text-ink-muted font-normal">
              {" "}
              · {incident.status === "RESOLVED" ? "resolved in " : ""}
              {incident.latency_ms}ms
            </span>
          ) : null}
        </div>
      </div>

      <p className="text-[11px] text-ink-muted mt-3">
        Approvals and the incident feed live in this web app; Discord is an
        optional mirror.
      </p>
    </Card>
  );
}
