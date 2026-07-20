import type { Device, DeviceKind, DeviceMetrics, DeviceStatus } from "./types";

// Static device metadata mirror of config/device_registry.json — used for demo data
// and as enrichment fallback. The LIVE device list/status always comes from the API
// (/api/devices, /api/state) so new/connected devices appear without editing this.
export const DEVICE_REGISTRY: Record<
  string,
  { model: string; solution_track: number; owner: string; firmware: string; registry_status: string; notes: string }
> = {
  "esp32-cam-01": {
    model: "ESP32-CAM",
    solution_track: 1,
    owner: "Vy",
    firmware: "open",
    registry_status: "live",
    notes: "Live device. Solution 1 — OTA patch pipeline.",
  },
  "esp32-cam-02": {
    model: "ESP32-CAM",
    solution_track: 1,
    owner: "Vy",
    firmware: "open",
    registry_status: "bench-ready",
    notes: "Bench-ready. Same code path — proves the pipeline scales horizontally.",
  },
  "esp32-cam-03": {
    model: "ESP32-CAM",
    solution_track: 1,
    owner: "Vy",
    firmware: "open",
    registry_status: "bench-ready",
    notes: "Bench-ready. Same code path — proves the pipeline scales horizontally.",
  },
  "tapo-c200-01": {
    model: "TP-Link Tapo C200",
    solution_track: 2,
    owner: "Duc",
    firmware: "closed",
    registry_status: "live",
    notes: "Reference device for Solution 2 — three-source network whitelist.",
  },
};

export function deviceKind(model: string): DeviceKind {
  return /cam|camera|tapo|c200|hikvision|reolink|webcam|doorbell/i.test(model || "") ? "camera" : "generic";
}

export function normalizeStatus(s: string | undefined | null): DeviceStatus {
  const v = (s || "").toLowerCase();
  if (v === "attack" || v === "attacked" || v === "compromised") return "attack";
  if (v === "elevated" || v === "elevating") return "elevated";
  if (v === "warming" || v === "warmup" || v === "warming-up") return "warming";
  if (v === "offline" || v === "disconnected") return "offline";
  return "clean";
}

// nominal "normal response" baseline per device kind (used when the API has no baseline)
export function defaultBaseline(model: string): DeviceMetrics {
  if (/tapo|c200/i.test(model)) {
    return { cpu_percent: 16, memory_percent: 44, packet_rate: 28, connection_count: 2 };
  }
  return { cpu_percent: 21, memory_percent: 38, packet_rate: 47, connection_count: 1 };
}
