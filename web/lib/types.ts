// ─── Shared data contract for the AES web app ──────────────────────────────────
// Mirrors the backend artifacts (config/fleet_status.json, config/device_registry.json,
// aes_incidents.jsonl, config/skills.jsonl) surfaced via dashboard/app.py.

export type DeviceStatus = "clean" | "warming" | "elevated" | "attack" | "offline";
export type DeviceKind = "camera" | "generic";

export interface DeviceMetrics {
  cpu_percent: number;
  memory_percent: number;
  packet_rate: number;
  connection_count: number;
}

export interface Device {
  id: string;
  model: string;
  kind: DeviceKind;
  owner: string;
  solution_track: number;
  firmware: string; // "open" | "closed"
  registry_status: string; // "live" | "bench-ready"
  connected: boolean;
  status: DeviceStatus; // live runtime detection status
  metrics: DeviceMetrics;
  baseline: DeviceMetrics; // normal-response reference
  last_seen: string; // "HH:MM:SS"
}

export type Deviations = Record<string, number>; // metric -> fractional deviation (0.5 = +50%)

export interface Verdict {
  solution_track?: number;
  action?: string; // PATCH_OTA | BLOCK_FIREWALL | REWRITE_SKILL | INVESTIGATE
  cve_id?: string;
  confidence?: number;
  reasoning?: string;
}

export interface GateResult {
  rule_id: string;
  label: string;
  passed: boolean;
  note?: string;
}

// remediation payload — adapts by solution track (1 = OTA patch, 2 = firewall whitelist)
export interface PatchData {
  diff?: string; // unified diff (Solution 1)
  gates?: GateResult[]; // Semgrep gate results (Solution 1)
  whitelist?: string[]; // 3-source network whitelist rules (Solution 2)
}

export interface Incident {
  incident_id: string;
  timestamp: string;
  device_id: string;
  device_model?: string;
  solution_track?: number;
  confidence: number;
  reason: string;
  deviations: Deviations;
  baseline: Record<string, number>;
  status: "OPEN" | "RESOLVED" | "FAILED" | "MANUAL_REVIEW";
  resolved_at?: string;
  latency_ms?: number;
  cve_id?: string;
  cve_severity?: string;
  cve_score?: number;
  verdict?: Verdict;
  patch?: PatchData;
  stage?: string; // live pipeline progress marker written by the agents (e.g. "gate1_passed")
}

export interface Benchmark {
  detection_rate: number; // 0..1
  false_positive_rate: number; // 0..1
  latency_ms?: number;
  sample_size?: number;
  normal_sample_size?: number;
}

export interface Skill {
  skill_id: string;
  version?: number;
  created_at?: string;
  incident_id?: string;
  cve_id?: string;
  device_type?: string;
  attack_signature?: string;
  params: { deviation_threshold?: number; simultaneous_threshold?: number };
  diff?: string;
  benchmark?: Benchmark;
  status: "PENDING_HITL" | "APPROVED" | "INJECTED" | "REJECTED" | string;
  approved_by?: string;
  approved_at?: string;
}

export interface ThresholdPoint {
  label: string;
  threshold: number;
  detection_rate?: number;
}

export interface AesState {
  fleet: Record<
    string,
    {
      status: string;
      cpu_percent: number;
      memory_percent?: number;
      packet_rate: number;
      connection_count: number;
      last_seen: string;
    }
  >;
  incidents: Incident[];
  pending: Skill[];
  active_params: { deviation_threshold: number; simultaneous_threshold: number };
  history: ThresholdPoint[];
}

// one polled sample, used to build live rolling charts on the client
export interface Sample {
  t: number; // ms timestamp / sequence
  cpu: number;
  mem: number;
  packet: number;
  conn: number;
}

// agent pipeline stage descriptor (incident theater)
export interface PipelineStage {
  key: string;
  name: string;
  sub: string;
  state: "done" | "active" | "idle" | "optional";
}
