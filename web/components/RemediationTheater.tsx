"use client";

import type { Device, GateResult, Incident } from "@/lib/types";
import { Card, Chip, EmptyState } from "@/components/ui";
import { cx } from "@/lib/format";

const WAITING_DIFF = "// waiting for Hermes to generate a patch…";

// The 4 checks gates/semgrep/aes_rules.yaml runs — shown as pending until
// agents/response_agent.py actually runs Gate 1 and reports real pass/fail.
const PENDING_GATES: GateResult[] = [
  { rule_id: "CWE-119", label: "buffer overflow", passed: false },
  { rule_id: "CWE-416", label: "use-after-free", passed: false },
  { rule_id: "CWE-78", label: "command injection", passed: false },
  { rule_id: "CWE-798", label: "hardcoded creds", passed: false },
];

interface Stage {
  name: string;
  sub: string;
  log: string;
  sim?: boolean;
}

// Maps the real `incident.stage` values written by agents/response_agent.py to
// a step index into sol1Stages/sol2Stages below, and which stages are terminal
// failures vs. a normal (if hardware-less) completion.
const SOL1_STEP: Record<string, number> = {
  vuln_confirmed: 0,
  patch_generated: 1,
  patch_failed: 1,
  gate1_running: 2,
  gate1_failed: 2,
  gate1_passed: 3,
  building: 3,
  build_failed: 3,
  no_hardware: 3,
  flashing: 4,
  flash_failed: 4,
  validating: 5,
  boot_timeout: 5,
  boot_confirmed: 6,
};
const SOL1_FAILED = new Set(["patch_failed", "gate1_failed", "build_failed", "flash_failed", "boot_timeout"]);
// Terminal-but-not-failed stages: the pipeline stopped here on purpose and
// nothing further will happen, so the active box must read as settled, not
// "still running" — otherwise it looks stuck forever.
const SOL1_DONE = new Set(["boot_confirmed"]);
// OTA flash/self-validate/commit aren't wired up to real hardware yet — Gate 1
// passing is treated as the full success path, with the remaining boxes shown
// as simulated-complete rather than stuck pending forever.
const SOL1_CAPPED = new Set(["no_hardware"]);
const SOL2_DONE = new Set(["verified"]);
const SOL1_NOTE: Record<string, string> = {
  patch_failed: "Hermes diff could not be applied to the source",
  gate1_failed: "Gate 1 rejected the patch — held for manual review",
  build_failed: "firmware build failed",
  flash_failed: "OTA flash failed",
  boot_timeout: "device didn't confirm boot — may have rolled back",
  no_hardware: "patch live — incident resolved (OTA flash simulated; hardware not wired up yet)",
  boot_confirmed: "patch live — incident resolved",
};

const SOL2_STEP: Record<string, number> = {
  vuln_confirmed: 0,
  whitelist_built: 1,
  dry_run: 2,
  enforced: 3,
  verified: 4,
};

function StepIcon({ state }: { state: "done" | "running" | "failed" | "pending" }) {
  if (state === "done")
    return (
      <span className="flex h-4 w-4 items-center justify-center rounded-full bg-clean text-[10px] font-bold text-white">✓</span>
    );
  if (state === "failed")
    return (
      <span className="flex h-4 w-4 items-center justify-center rounded-full bg-attack text-[10px] font-bold text-white">✕</span>
    );
  if (state === "running") return <span className="h-4 w-4 animate-spin rounded-full border-2 border-data border-t-transparent" />;
  return <span className="h-4 w-4 rounded-full border-2 border-line" />;
}

// `settled` = the active box is a deliberate stopping point (success or
// failure), not work-in-progress — so it must not render as "still running".
// `capped` additionally marks every box AFTER the active one as done-but
// -simulated (OTA flash/validate/commit aren't wired to real hardware yet,
// so once Gate 1 passes the rest of the run is shown as a simulated success
// instead of stuck "pending" forever).
function Stepper({ stages, step, failed, settled, capped }: { stages: Stage[]; step: number; failed: boolean; settled: boolean; capped: boolean }) {
  return (
    <ol className="space-y-2.5">
      {stages.map((st, i) => {
        const state = i < step ? "done" : i === step ? (failed ? "failed" : settled ? "done" : "running") : capped ? "done" : "pending";
        const simulated = st.sim || (capped && i >= step);
        return (
          <li key={st.name} className="flex items-start gap-3">
            <span className="mt-0.5">
              <StepIcon state={state} />
            </span>
            <div className="min-w-0">
              <div
                className={cx(
                  "text-[12px] font-medium",
                  state === "pending" ? "text-ink-muted" : state === "failed" ? "text-attack" : state === "running" ? "text-data" : "text-ink"
                )}
              >
                {st.name}
              </div>
              <div className="text-[11px] text-ink-muted">
                {st.sub}
                {simulated ? " · simulated" : ""}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function LiveConsole({ stages, step, failed, settled, capped, note }: { stages: Stage[]; step: number; failed: boolean; settled: boolean; capped: boolean; note?: string }) {
  const shown = capped ? stages : stages.slice(0, Math.min(step + 1, stages.length));
  return (
    <div className="rounded-lg border border-line bg-surface-2 p-3 font-mono text-[11px] leading-relaxed">
      <div className="mb-1 text-[10px] uppercase tracking-wider text-ink-muted">live log</div>
      {shown.map((st, i) => {
        const active = i === step;
        const simulated = capped && i >= step;
        const tone = capped ? "text-clean" : !active ? "text-ink-2" : failed ? "text-attack" : settled ? "text-clean" : "text-data";
        const bullet = capped ? "✓" : i < step ? "✓" : active && failed ? "✕" : active && settled ? "✓" : "→";
        return (
          <div key={st.name} className={tone}>
            <span className={active && failed ? "text-attack" : "text-clean"}>{bullet}</span>{" "}
            {active && failed ? note ?? st.log : st.log}
            {simulated ? " (simulated)" : ""}
            {active && !failed && !settled && <span className="ml-0.5 animate-pulse">▋</span>}
          </div>
        );
      })}
    </div>
  );
}

function DiffBlock({ diff }: { diff: string }) {
  return (
    <pre className="overflow-x-auto rounded-xl border border-line bg-surface-2 p-3 font-mono text-xs leading-relaxed">
      {diff.split("\n").map((ln, i) => {
        let tone = "text-ink-2";
        if (ln.startsWith("-")) tone = "text-attack line-through";
        else if (ln.startsWith("+")) tone = "text-clean font-semibold";
        else if (ln.startsWith("@@")) tone = "text-ink-muted";
        return (
          <div key={i} className={tone}>
            {ln === "" ? " " : ln}
          </div>
        );
      })}
    </pre>
  );
}

export default function RemediationTheater({ device, incident }: { device: Device; incident?: Incident }) {
  const track = incident?.solution_track ?? device.solution_track;

  const sol1Stages: Stage[] = [
    { name: "Vulnerability confirmed", sub: incident?.cve_id ?? "CVE", log: `detected ${incident?.cve_id ?? "CVE"} — heap-overflow signature` },
    { name: "Patch generated", sub: "Hermes · unified diff", log: "Hermes generated a patch" },
    { name: "Gate 1 · Semgrep", sub: "static analysis", log: "running Semgrep CWE-119/416/78/798…" },
    { name: "Gate 2 · Boot-diff", sub: "harness", sim: true, log: "soft-skipped (harness not wired yet)" },
    { name: "OTA flash · ota_1", sub: "dual-partition", log: "flashing ota_1 …" },
    { name: "Self-validate (30s)", sub: "WiFi + MQTT", log: "waiting for ota_1 boot confirmation…" },
    { name: "Committed", sub: "patch live", log: "committed ota_1 — incident RESOLVED" },
  ];
  const sol2Stages: Stage[] = [
    { name: "Anomaly confirmed", sub: incident?.cve_id ?? "CVE", log: `detected ${incident?.cve_id ?? "CVE"} — closed firmware, cannot patch` },
    { name: "Build 3-source whitelist", sub: "spec + baseline + CVE", log: "composed allow / deny rule set" },
    { name: "Dry-run", sub: "no traffic impact", log: "dry-run: legitimate flows preserved" },
    { name: "Enforce at gateway", sub: "firewall", log: "wrote quarantine rule at gateway" },
    { name: "Verified", sub: "egress dropped", log: "malicious egress dropped — contained" },
  ];

  const isSol2 = track === 2;
  const stages = isSol2 ? sol2Stages : sol1Stages;
  const stageKey = incident?.stage;
  const stepMap = isSol2 ? SOL2_STEP : SOL1_STEP;
  const step = stageKey !== undefined ? stepMap[stageKey] ?? 0 : 0;
  const failed = !isSol2 && !!stageKey && SOL1_FAILED.has(stageKey);
  const capped = !isSol2 && !!stageKey && SOL1_CAPPED.has(stageKey);
  const done = !!stageKey && (isSol2 ? SOL2_DONE.has(stageKey) : SOL1_DONE.has(stageKey));
  const settled = failed || capped || done;
  const note = !isSol2 && stageKey ? SOL1_NOTE[stageKey] : undefined;

  if (!incident) {
    return (
      <Card title="Remediation theater" accent="info">
        <EmptyState title="No remediation in flight" hint="No patch or firewall action is pending — this device is nominal." icon="🛠️" />
      </Card>
    );
  }

  if (incident.status === "MANUAL_REVIEW") {
    return (
      <Card title="Remediation theater" accent="info">
        <EmptyState
          title="Held for manual review"
          hint={`Hermes confidence ${Math.round((incident.verdict?.confidence ?? incident.confidence) * 100)}% was below the auto-execute threshold — no patch or firewall action was taken.`}
          icon="⏸️"
        />
      </Card>
    );
  }

  const verdict = incident.verdict;
  const patch = incident.patch;
  const otaPct = capped ? 100 : Math.round((Math.min(step, stages.length - 1) / (stages.length - 1)) * 100);

  if (track === 2) {
    const whitelist =
      patch?.whitelist && patch.whitelist.length
        ? patch.whitelist
        : [
            `allow  ${device.id} -> 192.168.1.1:443    cloud heartbeat (manufacturer spec)`,
            `allow  ${device.id} -> 192.168.1.10:554   RTSP to NVR (fresh-flash baseline)`,
            `deny   ${device.id} -> 0.0.0.0/0          default-deny everything else`,
          ];
    return (
      <Card title="Remediation theater · Solution 2 (firewall)" accent="info">
        <div className="grid gap-5 md:grid-cols-2">
          <div className="space-y-4">
            <Stepper stages={stages} step={step} failed={false} settled={settled} capped={false} />
            <LiveConsole stages={stages} step={step} failed={false} settled={settled} capped={false} />
          </div>
          <div className="space-y-4">
            <div>
              <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-2">3-source network whitelist</h4>
              <pre className="overflow-x-auto rounded-xl border border-line bg-surface-2 p-3 font-mono text-xs leading-relaxed">
                {whitelist.map((ln, i) => (
                  <div key={i} className={ln.startsWith("allow") ? "text-clean" : ln.startsWith("deny") ? "text-attack" : "text-ink-2"}>
                    {ln}
                  </div>
                ))}
              </pre>
            </div>
            <Card accent="info">
              <div className="text-sm font-semibold text-info">{verdict?.action ?? "BLOCK_FIREWALL"}</div>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                {incident.cve_id && <Chip tone="info">{incident.cve_id}</Chip>}
                <span className="font-mono text-[11px] text-ink-2">confidence {verdict?.confidence ?? incident.confidence}</span>
              </div>
              <div className="mt-2 text-[11px] text-ink-muted">
                {step >= stages.length - 1 ? "egress dropped — device contained" : "building + enforcing quarantine…"}
              </div>
            </Card>
          </div>
        </div>
      </Card>
    );
  }

  // Solution 1 (OTA)
  const diff = patch?.diff || WAITING_DIFF;
  const gatesRun = !!(patch?.gates && patch.gates.length);
  const gates = gatesRun ? patch!.gates! : PENDING_GATES;
  const part1 = capped ? "committed (simulated)" : step >= 6 ? "committed" : step >= 5 ? "validated" : step >= 4 ? "writing…" : "ready";

  return (
    <Card title="Patch theater · Solution 1 (OTA)" accent="clean">
      <div className="grid gap-5 md:grid-cols-2">
        <div className="space-y-4">
          <Stepper stages={stages} step={step} failed={failed} settled={settled} capped={capped} />
          <LiveConsole stages={stages} step={step} failed={failed} settled={settled} capped={capped} note={note} />
          <div>
            <div className="mb-1.5 flex items-center justify-between text-[11px] text-ink-2">
              <span className="font-medium">OTA flash · dual-partition</span>
              <span className="font-mono text-ink-muted">{otaPct}%</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-surface-2">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{ width: `${otaPct}%`, background: "linear-gradient(90deg,#0891B2,#2563EB)" }}
              />
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              <Chip tone="data">ota_0 · running</Chip>
              <Chip tone="info">ota_1 · {part1}</Chip>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div>
            <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-2">Unified diff</h4>
            <DiffBlock diff={diff} />
          </div>
          <div>
            <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-2">Gate 1 · Semgrep</h4>
            <ul className="space-y-2">
              {gates.map((g) => (
                <li key={g.rule_id} className="flex items-center gap-2.5 rounded-lg border border-line bg-surface px-3 py-2">
                  <span
                    className={cx(
                      "flex h-4 w-4 shrink-0 items-center justify-center rounded border text-[10px] font-bold",
                      !gatesRun ? "border-line text-ink-muted" : g.passed ? "border-clean text-clean" : "border-attack text-attack"
                    )}
                  >
                    {!gatesRun ? "" : g.passed ? "✓" : "✕"}
                  </span>
                  <div className="min-w-0">
                    <div className="font-mono text-[11px] text-ink">{g.rule_id}</div>
                    <div className="truncate text-[11px] text-ink-2">{g.label}</div>
                  </div>
                  <span className="ml-auto shrink-0 text-[11px] text-ink-muted">
                    {!gatesRun ? (stageKey === "gate1_running" ? "scanning…" : "pending") : g.note ?? (g.passed ? "pass" : "fail")}
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <Card accent="clean">
            <div className="text-sm font-semibold text-clean">{verdict?.action ?? "PATCH_OTA"}</div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {incident.cve_id && <Chip tone="data">{incident.cve_id}</Chip>}
              <span className="font-mono text-[11px] text-ink-2">confidence {verdict?.confidence ?? incident.confidence}</span>
            </div>
            <div className={cx("mt-2 text-[11px]", failed ? "text-attack" : "text-ink-muted")}>
              {note ?? (gatesRun ? "Gate 1 PASS — flashing" : "awaiting patch + Gate 1…")}
            </div>
          </Card>
        </div>
      </div>
    </Card>
  );
}
