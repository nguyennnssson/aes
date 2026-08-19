"use client";

import { useEffect, useRef, useState } from "react";
import type { AesState, Device, Sample } from "./types";
import { mockDevices, mockState, stepMockDevices } from "./mock";

// Demo mode (default in dev) uses bundled sample data so the whole UI is viewable.
// Turn it off + run the FastAPI backend to show only live, connected devices.
export const DEMO = process.env.NEXT_PUBLIC_DEMO === "1";

function authHeaders(): HeadersInit {
  if (typeof window === "undefined") return {};
  let token = window.sessionStorage.getItem("aesDashboardToken") ?? "";
  if (!token && !DEMO) {
    token = window.prompt("Enter the AES dashboard token") ?? "";
    if (token) window.sessionStorage.setItem("aesDashboardToken", token);
  }
  return token ? { "X-AES-Admin-Token": token } : {};
}

async function getJSON<T>(url: string): Promise<T> {
  const r = await fetch(url, { cache: "no-store", headers: authHeaders() });
  if (!r.ok) throw new Error(`${url} → ${r.status}`);
  return (await r.json()) as T;
}

export const fetchDevices = () => getJSON<Device[]>("/api/devices");
export const fetchState = () => getJSON<AesState>("/api/state");
export const approveSkill = (id: string) => fetch(`/api/approve/${encodeURIComponent(id)}`, { method: "POST", headers: authHeaders() });
export const rejectSkill = (id: string) => fetch(`/api/reject/${encodeURIComponent(id)}`, { method: "POST", headers: authHeaders() });

// ─── explicitly simulated cam-01 dashboard scenario ──────────────────────────
export const runDemoAttack = () => fetch("/api/demo/cam01/attack", { method: "POST", headers: authHeaders() });
export const runDemoReset = () => fetch("/api/demo/cam01/reset", { method: "POST", headers: authHeaders() });

// ─── live fleet (device list + status), polled ────────────────────────────────
export function useDevices(pollMs = 2000) {
  const [devices, setDevices] = useState<Device[]>(() => (DEMO ? mockDevices() : []));
  const [live, setLive] = useState(false);
  const [loading, setLoading] = useState(!DEMO);

  useEffect(() => {
    let alive = true;
    let demoFleet = mockDevices();
    async function tick() {
      if (DEMO) {
        demoFleet = stepMockDevices(demoFleet);
        if (alive) setDevices(demoFleet);
        return;
      }
      try {
        const d = await fetchDevices();
        if (alive) {
          setDevices(d);
          setLive(true);
          setLoading(false);
        }
      } catch {
        if (alive) {
          setLive(false);
          setLoading(false);
        }
      }
    }
    tick();
    const id = setInterval(tick, pollMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [pollMs]);

  return { devices, live, loading, demo: DEMO };
}

export function useDevice(id: string, pollMs = 2000) {
  const fleet = useDevices(pollMs);
  return { ...fleet, device: fleet.devices.find((d) => d.id === id) };
}

// ─── incidents / skills / history, polled ─────────────────────────────────────
export function useAesState(pollMs = 3000) {
  const [state, setState] = useState<AesState | null>(() => (DEMO ? mockState() : null));
  useEffect(() => {
    let alive = true;
    async function tick() {
      if (DEMO) {
        if (alive) setState(mockState());
        return;
      }
      try {
        const s = await fetchState();
        if (alive) setState(s);
      } catch {
        /* keep last good state */
      }
    }
    tick();
    const id = setInterval(tick, pollMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [pollMs]);
  return state;
}

// ─── per-device rolling history for live charts ───────────────────────────────
const sampleFrom = (d: Device, t: number): Sample => ({
  t,
  cpu: d.metrics.cpu_percent,
  mem: d.metrics.memory_percent,
  packet: d.metrics.packet_rate,
  conn: d.metrics.connection_count,
});

export function useDeviceHistory(device: Device | undefined, len = 48, stepMs = 1500): Sample[] {
  const [hist, setHist] = useState<Sample[]>([]);
  const ref = useRef(device);
  ref.current = device;
  const seq = useRef(0);

  // reset + seed when the device changes so the chart has width immediately
  useEffect(() => {
    seq.current = 0;
    if (!device) {
      setHist([]);
      return;
    }
    setHist(Array.from({ length: 14 }, () => sampleFrom(device, seq.current++)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device?.id]);

  // append the latest reading on a fixed cadence
  useEffect(() => {
    const id = setInterval(() => {
      const d = ref.current;
      if (!d) return;
      setHist((h) => [...h, sampleFrom(d, seq.current++)].slice(-len));
    }, stepMs);
    return () => clearInterval(id);
  }, [len, stepMs]);

  return hist;
}
