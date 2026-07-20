import type { AesState, Device, Incident, Skill } from "./types";
import { defaultBaseline, deviceKind } from "./registry";

// ─── DEMO DATA ─────────────────────────────────────────────────────────────────
// Rich sample fleet so the UI is fully viewable without the backend. When NEXT_PUBLIC_DEMO
// is off and the FastAPI backend runs, the app shows only live, connected devices instead.

const DIFF = `@@ esp32-cam/main/handler.c @@
  void on_packet(char *buf) {
-     strcpy(dest, buf);
+     strlcpy(dest, buf, sizeof(dest));
      process(dest);
  }`;

function base(
  id: string,
  model: string,
  solution_track: number,
  owner: string,
  firmware: string,
  registry_status: string,
  status: Device["status"],
  metrics: Device["metrics"]
): Device {
  return {
    id,
    model,
    kind: deviceKind(model),
    owner,
    solution_track,
    firmware,
    registry_status,
    connected: true,
    status,
    metrics,
    baseline: defaultBaseline(model),
    last_seen: "live",
  };
}

export function mockDevices(): Device[] {
  return [
    base("esp32-cam-01", "ESP32-CAM", 1, "Vy", "open", "live", "clean", {
      cpu_percent: 21,
      memory_percent: 38,
      packet_rate: 47,
      connection_count: 1,
    }),
    base("esp32-cam-02", "ESP32-CAM", 1, "Vy", "open", "live", "attack", {
      cpu_percent: 88,
      memory_percent: 57,
      packet_rate: 512,
      connection_count: 47,
    }),
    base("esp32-cam-03", "ESP32-CAM", 1, "Vy", "open", "bench-ready", "clean", {
      cpu_percent: 23,
      memory_percent: 40,
      packet_rate: 51,
      connection_count: 1,
    }),
    base("tapo-c200-01", "TP-Link Tapo C200", 2, "Duc", "closed", "live", "elevated", {
      cpu_percent: 39,
      memory_percent: 48,
      packet_rate: 96,
      connection_count: 8,
    }),
  ];
}

const noise = (v: number, pct: number) => Math.max(0, v * (1 + (Math.random() - 0.5) * pct));

function target(status: Device["status"], b: Device["metrics"]): Device["metrics"] {
  switch (status) {
    case "attack":
      return { cpu_percent: 88, memory_percent: b.memory_percent * 1.45, packet_rate: 512, connection_count: 47 };
    case "elevated":
      return {
        cpu_percent: b.cpu_percent * 2.4,
        memory_percent: b.memory_percent * 1.15,
        packet_rate: b.packet_rate * 3.2,
        connection_count: b.connection_count + 6,
      };
    case "warming":
      return {
        cpu_percent: b.cpu_percent * 1.6,
        memory_percent: b.memory_percent * 1.05,
        packet_rate: b.packet_rate * 1.8,
        connection_count: b.connection_count + 2,
      };
    default:
      return { ...b };
  }
}

// advance the demo fleet one tick so live charts actually move
export function stepMockDevices(prev: Device[]): Device[] {
  return prev.map((d) => {
    const t = target(d.status, d.baseline);
    const amt = d.status === "clean" ? 0.1 : d.status === "attack" ? 0.08 : 0.14;
    return {
      ...d,
      metrics: {
        cpu_percent: Math.min(100, noise(t.cpu_percent, amt)),
        memory_percent: Math.min(100, noise(t.memory_percent, amt)),
        packet_rate: noise(t.packet_rate, amt),
        connection_count: Math.round(noise(t.connection_count, amt)),
      },
    };
  });
}

function incCam02(): Incident {
  return {
    incident_id: "INC-2138-cam02",
    timestamp: "21:38:41",
    device_id: "esp32-cam-02",
    device_model: "ESP32-CAM",
    solution_track: 1,
    confidence: 0.97,
    reason: "cpu +299%, packet_rate +953% — 2 rules fired simultaneously",
    deviations: { cpu_percent: 2.99, packet_rate: 9.53, connection_count: 14.66 },
    baseline: { cpu_percent: 21, packet_rate: 47, connection_count: 1, memory_percent: 38 },
    status: "RESOLVED",
    resolved_at: "21:38:43",
    latency_ms: 312,
    cve_id: "CVE-2021-34173",
    cve_severity: "HIGH",
    cve_score: 9.8,
    verdict: {
      solution_track: 1,
      action: "PATCH_OTA",
      cve_id: "CVE-2021-34173",
      confidence: 0.91,
      reasoning:
        "ESP32 heap overflow consistent with a Mirai C2 beacon. OTA patch hardens the vulnerable strcpy.",
    },
    patch: {
      diff: DIFF,
      gates: [
        { rule_id: "CWE-119", label: "buffer overflow", passed: true, note: "resolved" },
        { rule_id: "CWE-416", label: "use-after-free", passed: true },
        { rule_id: "CWE-78", label: "command injection", passed: true },
        { rule_id: "CWE-798", label: "hardcoded creds", passed: true },
      ],
    },
  };
}

function incTapo(): Incident {
  return {
    incident_id: "INC-2140-tapo",
    timestamp: "21:40:05",
    device_id: "tapo-c200-01",
    device_model: "TP-Link Tapo C200",
    solution_track: 2,
    confidence: 0.74,
    reason: "packet_rate +242%, connection_count +300% — sustained low-and-slow",
    deviations: { packet_rate: 2.42, connection_count: 3.0, cpu_percent: 1.44 },
    baseline: { cpu_percent: 16, packet_rate: 28, connection_count: 2, memory_percent: 44 },
    status: "MANUAL_REVIEW",
    cve_id: "CVE-2021-4045",
    cve_severity: "CRITICAL",
    cve_score: 9.8,
    verdict: {
      solution_track: 2,
      action: "BLOCK_FIREWALL",
      cve_id: "CVE-2021-4045",
      confidence: 0.78,
      reasoning: "Closed firmware — cannot patch. Quarantine at the gateway via a 3-source whitelist.",
    },
    patch: {
      whitelist: [
        "allow  tapo-c200-01 → 192.168.1.1:443    cloud heartbeat (manufacturer spec)",
        "allow  tapo-c200-01 → 192.168.1.10:554   RTSP to NVR (fresh-flash baseline)",
        "deny   tapo-c200-01 → 0.0.0.0/0          default-deny everything else",
      ],
    },
  };
}

export function mockSkill(): Skill {
  return {
    skill_id: "skill-7f3a2c1b",
    version: 2,
    created_at: "21:38:50",
    incident_id: "INC-2138-cam02",
    cve_id: "CVE-2021-34173",
    device_type: "ESP32-CAM",
    attack_signature: "cpu + packet_rate simultaneous spike",
    params: { deviation_threshold: 0.35, simultaneous_threshold: 2 },
    diff: DIFF,
    benchmark: { detection_rate: 0.91, false_positive_rate: 0.04, latency_ms: 312, sample_size: 240, normal_sample_size: 600 },
    status: "PENDING_HITL",
  };
}

export function mockState(): AesState {
  return {
    fleet: {},
    incidents: [incCam02(), incTapo()],
    pending: [mockSkill()],
    active_params: { deviation_threshold: 0.35, simultaneous_threshold: 2 },
    history: [
      { label: "v1 (ship)", threshold: 0.5, detection_rate: 0.8 },
      { label: "deploy 1", threshold: 0.45, detection_rate: 0.84 },
      { label: "deploy 2", threshold: 0.4, detection_rate: 0.91 },
      { label: "now", threshold: 0.35, detection_rate: 0.95 },
    ],
  };
}
