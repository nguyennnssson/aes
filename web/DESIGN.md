# AES Web App — Design & Status

> Status: **BUILT — Next.js app running.** Device-centric, light theme, live-wired with a demo fallback.
> Last updated: 2026-06-17. Owner: front-end.
> Run: `npm run dev` in `web/` → http://localhost:3000. Legacy static mockup: `web/preview.html` (superseded by this app).

## 1. What it is
A **device-centric** IoT security control plane for AES (Autonomous Edge-Sentinel). A left sidebar
lists the **live, connected devices** (only devices currently sending signals appear). Each device
has its **own page** with everything about it: simulated camera feed, live signal graphs (normal vs
under attack), metrics/stats, its **incident theater** (the agent pipeline) and its **remediation
theater** (adapts to the device's solution track). The **Self-Improvement** (Hermes learning loop)
is its own page. Built to be user-friendly and to make devices, data, graphs and status stand out.

## 2. Locked decisions (current)
- **Stack:** Next.js 14 (App Router, TS) + Tailwind + Recharts. React 18. Node 24.
- **Theme:** **LIGHT background, dark fonts**, vivid semantic color accents (user directive — replaces
  the earlier monochrome and dark explorations).
- **Information architecture:** **device-centric.** Left sidebar = Overview + one tab per **live**
  device (the tab animates by status) + Self-Improvement. No multi-page hopping for a device — its
  signals, theaters and stats are all on its own page.
- **Data:** **live-wired** to the FastAPI backend with a **demo fallback** so the UI is always viewable.
  - Live device list/status comes from the API (`/api/devices`, `/api/state`) — **only connected
    devices that are sending signals are shown**; the list is not hardcoded.
  - **Live by default** (`NEXT_PUBLIC_DEMO=0`): run the backend (`uvicorn dashboard.app:app --port 8000`)
    plus `python scripts/live_demo.py` — a broker-free fleet driver that refreshes `fleet_status.json`
    every 2s and seeds incidents/skills. Set `NEXT_PUBLIC_DEMO=1` for standalone sample data (no backend).
- **Control plane:** the web app is primary (incident feed + HITL approve/reject). Discord optional.

## 3. Design language (light / color-accented)
Tokens live in `web/tailwind.config.ts`; animations in `web/app/globals.css`.

| Token | Hex | Use |
|---|---|---|
| page | `#F6F8FB` | app background |
| surface / surface-2 | `#FFFFFF` / `#EEF2F7` | cards / inset |
| line / line-strong | `#E3E8EF` / `#CBD5E1` | borders |
| ink / ink-2 / ink-muted | `#0D1626` / `#475569` / `#94A3B8` | text |
| clean | `#16A34A` | clean · **normal response** |
| warming | `#CA8A04` | warming |
| elevated | `#EA580C` | elevated |
| attack | `#DC2626` | **attack** · critical |
| info / data / ai | `#2563EB` / `#0891B2` / `#7C3AED` | info · live data · Hermes/AI |

**Status with color + motion:** each device tab/card carries its status color and a status animation
(`anim-breathe-green` clean, `anim-pulse-amber` warming/elevated, `anim-pulse-red` attack) so an
attack is noticeable from anywhere. Charts: green = normal/baseline, red = under attack.

## 4. Pages & layout
- **`/` Overview** (`app/page.tsx`) — live KPI tiles (devices, open incidents, detect→respond,
  detection rate, skills) + a **device gallery** of cards (camera devices show a simulated feed,
  status pill, cpu sparkline, key stats, solution chip) + a recent-incident ticker. Empty state when
  no device is connected.
- **`/device/[id]`** (`app/device/[id]/page.tsx`) — the device's own page: big **camera feed** (cameras),
  **live metrics** (gauges + deviation tiles vs baseline), **normal-vs-attack signal scope** (cpu /
  packet_rate / connections), **IncidentTheater** (Device→Monitor→Intel→Hermes→Response→OpenClaw→
  Discord·optional + deviation bars + Hermes verdict), and a **RemediationTheater** — a **live
  stepping process** (animated stepper + streaming log + filling OTA progress) that adapts:
  Solution 1 → signed firmware diff + strict static/hardware gates + approval-bound serial install;
  Solution 2 → gateway identity verification and bidirectional quarantine. Camera panels are light
  (daylight scene) to fit the white theme. Empty state if the
  device isn't connected.
- **`/learning`** (`app/learning/page.tsx`) — Hermes self-improvement: pending **SkillCard**(s) with
  detection/false-positive gauges + Approve/Reject (wired to `/api/approve|reject`), detection-rate
  -over-time chart, before/after split.

## 5. Code map
```
web/
  app/            layout.tsx (sidebar shell) · globals.css · page.tsx · device/[id]/page.tsx · learning/page.tsx
  components/     Sidebar · DeviceCard · VideoPanel · IncidentTheater · RemediationTheater · SkillCard
                  ui.tsx (Card/Kpi/StatusPill/Chip/EmptyState/…) · charts.tsx (SignalScope/Gauge/ThresholdChart/Sparkline/BeforeAfter/DeviationBars)
  lib/            types.ts · format.ts (status→class) · registry.ts (kind/baseline) · api.ts (polling hooks) · mock.ts (demo fleet)
  tailwind.config.ts · next.config.mjs (proxies /api → :8000) · .env.local (NEXT_PUBLIC_DEMO=1)
```

## 6. Data API (backend = `dashboard/app.py`)
- `GET /api/devices` — **NEW**: live, connected-only device list (merges `config/device_registry.json`
  + `config/fleet_status.json`, derives kind/status/baseline). Devices not in fleet_status don't appear.
- `GET /api/state` — fleet + incidents + pending skills + active params + threshold history (existing).
- `POST /api/approve/{id}` · `POST /api/reject/{id}` — HITL skill actions (existing).
- CORS allows `localhost:3000` for dev.
- The client polls every ~2s and builds **rolling history** per device for the live charts.

## 7. Type-adaptive shell
`deviceKind(model)` (cameras vs generic) drives whether a video feed shows; `solution_track` drives the
remediation theater (1 = OTA, 2 = firewall). New device types/models drop in by extending these maps —
no per-device pages to write.

## 8. Run (live, default)
```
# Terminal 1 — backend:    uvicorn dashboard.app:app --port 8000   (Windows: add --app-dir <repo>)
# Terminal 2 — live data:  python scripts/live_demo.py             (broker-free fleet driver)
# Terminal 3 — web:        cd web && npm install && npm run dev    →  http://localhost:3000
# Standalone (no backend): set NEXT_PUBLIC_DEMO=1 in web/.env.local, then just run the web terminal.
```

## 9. Real vs simulated (honesty)
- **Real when live:** device list/status/metrics (fleet), incidents, Hermes verdicts, skill approve/inject,
  Gate 1 Semgrep results. **Simulated/representative:** camera video (styled placeholder), Gate 2 boot-diff,
  OTA flash animation. Labeled in the UI.

## 10. Remaining / next
- Optional SSE (`/api/stream`) to replace polling; per-device `/api/device/{id}/signal` history endpoint.
- More device-type templates (sensor / plug / lock) as hardware arrives.
- Wire a real ESP32 MJPEG feed into `VideoPanel` (stretch).
- Presenter/demo-mode driver + projector polish.
