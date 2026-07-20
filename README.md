# AES — Autonomous Edge-Sentinel

> *A self-healing, self-improving IoT security system, powered by OpenAI Codex + GPT-5.*

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)
![Powered by OpenAI](https://img.shields.io/badge/AI-Codex%20%2B%20GPT--5-black.svg)

---

## What It Does

IoT devices are attacked constantly. When one gets compromised, a security engineer has to manually investigate, diagnose, write a fix, and push an update — 4 to 8 hours per device. AES does this automatically in seconds, and **measurably gets better at detecting attacks after every incident**.

**Three solutions, one pipeline:**

| Solution | Target | Approach |
|---|---|---|
| 1 — OTA Patch | ESP32-CAM (open firmware) | Patches the vulnerability inside the device via esptool.py OTA |
| 2 — Network Whitelist | Tapo C200 (closed firmware) | Wraps the device in a 3-source iptables whitelist at the gateway |
| 3 — Self-Rewriting Detection | All devices | Hermes tunes its own EWMA detection parameters after every resolved incident — sandboxed, human-approved, hot-loaded live |

---

## Architecture

```
[Device Fleet]  ESP32-CAM / Tapo C200
                │  MQTT telemetry every 5s
                ▼
[Raspberry Pi]  Mosquitto broker (port 1883 → 8883 TLS in production)
                │  EWMA anomaly detection
                ▼
[Mac Studio]    Monitor Agent → Intel Agent (ChromaDB RAG) → Hermes → Response Agent
                                                                    │
                                              ┌─────────────────────┴───────────────┐
                                              ▼                                       ▼
                                   Discord #aes-alerts                  Solution 3 learning loop
                                                                  (propose → sandbox → approve → inject)
```

**Two AI agents:**
- **Hermes** — reasoning layer. CVE analysis, incident verdicts, firmware patch generation, and self-tuning detection parameters. Runs on OpenAI (see below).
- **OpenClaw** — execution layer. OTA flash, firewall writes, Discord alerts, skill injection.

**Telemetry contract (firmware ↔ monitor):** devices publish **raw** metrics to `aes/telemetry/{device_id}` as `{device_id, cpu_percent, memory_percent, packet_rate, connection_count}` (+ optional `timestamp`). The Monitor Agent owns the EWMA baseline and deviation math — the device only reports raw readings.

---

## Powered by OpenAI — Codex + GPT-5

The reasoning backend is swappable (`agents/llm_client.py`), and AES uses **two OpenAI models for two different jobs** — reasoning vs. writing code:

| Job | Where | Model | Why this model |
|---|---|---|---|
| Incident triage → verdict (action, CVE, confidence) | `Hermes.analyze_incident` | **GPT-5** (`HERMES_MODEL`) | Judgment over noisy telemetry + untrusted CVE context; structured JSON out. |
| Packet-window classification | `Hermes.classify_packet_window` | **GPT-5** | Fast reasoning call. |
| Self-tuning detection params | `skills/hitl.py` | **GPT-5** | Proposes safer EWMA thresholds from real incident/normal corpora. |
| **Firmware patch generation** | `Hermes.generate_patch` | **Codex** (`gpt-5-codex`, `HERMES_CODE_MODEL`) | Writes the minimal unified-diff C fix and iterates against Gate 1 (Semgrep) + Gate 2 (compile/boot) feedback — coding against verifiers, Codex's sweet spot. |

**Two backends** (set `HERMES_BACKEND`):
- `openai` — the OpenAI SDK with an `OPENAI_API_KEY`. **Default when a key is present.**
- `codex` — the local `codex` CLI (ChatGPT subscription auth, no API key). Default when no key is set.

Point `HERMES_MODEL` at a newer reasoning model (e.g. `gpt-6`) with no code change. If the OpenAI backend is unreachable, Hermes degrades to a local Llama 3 (Ollama) fallback rather than crashing the monitor.

---

## Solution 3 — the self-improvement loop (how it actually works)

A "skill" is a small set of EWMA detection **parameters** (e.g. `{"deviation_threshold": 0.4, "simultaneous_threshold": 2}`) — **not** executable code. There is no `exec()` anywhere in the loop.

1. A confirmed incident auto-triggers `HITLOrchestrator.propose_skill()` (cooldown-gated, one Hermes call per incident).
2. Hermes proposes tuned params; they're **validated and clamped** to safe bounds.
3. The **sandbox** replays real logged attacks (`aes_incidents.jsonl`) **and** real normal readings (`aes_normals.jsonl`) through the proposed params, measuring detection rate **and** false-positive rate. A skill **cannot** pass without a real normal corpus to prove against.
4. If it passes, the proposal + benchmark are posted to `#aes-alerts` for human ✅.
5. On approval, the injector **atomically** writes the params to `config/active_detection.json`. The running Monitor Agent polls that file by mtime and adopts the new params on its **next reading** — no restart, no `importlib.reload`, no cross-process surgery.

This makes the self-improvement a real, visible before/after: the same attack the old params miss gets caught after the loop deploys the new ones.

---

## Repository Structure

```
aes/
├── agents/
│   ├── monitor_agent.py         # EWMA detection (pure) + live param loading + tamper-evident log
│   ├── monitor_agent_mqtt.py    # MQTT subscriber — cooldown, try/finally, auto learning-loop trigger
│   ├── intel_agent.py           # Intel Agent — ChromaDB CVE search (degrades gracefully if Ollama down)
│   ├── hermes.py                # Hermes reasoning wrapper (analyze / patch / tune), timeouts on all calls
│   ├── fallback.py              # Offline fallback — Llama 3 8B via Ollama
│   └── response_agent.py        # Routes verdicts to Solution 1/2/3; holds INVESTIGATE/low-confidence
│   └── prompts/                 # hermes_system.md, patch_generation.md
├── rag/
│   ├── vector_store.py          # ChromaDB singleton (cosine, nomic-embed-text)
│   ├── embedder.py              # nomic-embed-text via Ollama, retry/backoff
│   ├── ingest_nvd.py            # RAG ingestion: NVD + Exploit-DB + ICS-CERT + Espressif
│   └── query_chromadb.py        # ad-hoc CVE search helper
├── skills/                      # Solution 3 learning loop (Son)
│   ├── schema.py                # Skill = params + benchmark + approval lifecycle
│   ├── store.py                 # JSONL persistence, latest-per-skill semantics
│   ├── sandbox.py               # replay benchmark (attacks + normals) — no exec
│   ├── inject.py                # atomic write to config/active_detection.json, auto-rollback
│   └── hitl.py                  # propose → sandbox → Discord → approve → inject (CLI + auto)
├── openclaw/                    # Execution layer (Duc)
│   ├── firewall.py              # platform backends: iptables (SSH→Pi) / pf / netsh
│   └── solution2.py             # quarantine executor: dry-run → enforce → verify → audit
├── discord/
│   └── discord_alerts.py        # Discord webhook — incident alerts + HITL approval (rate-limit safe)
├── config/
│   ├── device_registry.json     # Fleet config — device → solution track mapping
│   ├── ewma_baseline.json       # Pre-seeded baseline (committed) — avoids cold-start poisoning
│   ├── settings.py              # Typed settings, loads .env
│   └── .env.example             # Required environment variables
├── esp32-cam/                   # ESP32-CAM firmware (Vy) — dual-OTA + C telemetry agent
│   ├── main/main.c              # OTA validate/rollback + telemetry → aes/telemetry/{id}
│   ├── main/ewma.c              # EWMA in C
│   ├── partitions.csv           # dual-OTA: nvs/otadata/phy_init/ota_0/ota_1
│   └── OTA_LIFECYCLE.md         # rollback state machine
├── gates/
│   ├── semgrep/                 # Gate 1 (Vy) — aes_rules.yaml (CWE-119/416/78/798) + gate1.py
│   └── gate2.py                 # Gate 2 — Compile-Boot-Diff harness (structure/compile/boot-diff)
├── tests/
│   ├── diagnostic.py            # Environment health check
│   └── test_openai.py           # OpenAI API connectivity smoke test
├── telemetry_sim.py             # Hardware stub — normal / --attack / --stealth modes over MQTT
├── requirements.txt             # deps (paho-mqtt 1.x AND 2.x via agents/mqtt_compat.py)
└── test_all.sh                  # Full stack health check
```

Runtime files (gitignored, created as the system runs): `aes_incidents.jsonl`, `aes_incidents.hashes`, `aes_normals.jsonl`, `config/active_detection.json`, `config/previous_detection.json`, `config/skills.jsonl`, and the ESP-IDF `esp32-cam/build/` output.

---

## Setup

### 1 — Clone the repo

```bash
git clone https://github.com/nguyennnssson/aes.git
cd aes
```

### 2 — Install system dependencies (Mac)

```bash
brew install python@3.12 mosquitto ollama
```

### 3 — Create virtual environment

```bash
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4 — Connect OpenAI (pick one)

Hermes runs on OpenAI. Choose **either** backend — bring your own key or CLI:

**Option A — OpenAI API key.** Get a key from <https://platform.openai.com/api-keys> and:

```bash
export HERMES_BACKEND="openai"
export OPENAI_API_KEY="<your-key>"          # your key — never commit it
```

**Option B — Codex CLI (no API key).** Install the [Codex CLI](https://developers.openai.com/codex/cli) and sign in with your ChatGPT account (`codex login`), then:

```bash
export HERMES_BACKEND="codex"               # uses your ChatGPT subscription auth
```

Model selection (optional — sensible defaults shown):

```bash
export HERMES_MODEL="gpt-5"                 # reasoning model (point at gpt-6 when available)
export HERMES_CODE_MODEL="gpt-5-codex"      # Codex — firmware patch generation
```

Then copy `config/.env.example` to `.env` for the rest (or export directly, add to `~/.zshrc`):

```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."   # optional — incident alerts

# Optional — execution layer (defaults are the safe bench mode):
export AES_FLASH_ENFORCE=1             # Sol 1 actually builds+flashes (HITL-gated; default holds for approval)
export AES_FIREWALL_ENFORCE=1          # Sol 2 writes REAL firewall rules (gateway only)
export GATEWAY_SSH="pi@192.168.4.1"    # Sol 2 enforces on the Pi over SSH instead of locally
export AES_GATE2_STRICT=1              # Gate 2: skipped stages block the flash (production)
export GATE2_REFERENCE_PORT=COM7       # Gate 2 boot-diff: reference ESP32 serial port
export GATE2_REFERENCE_DEVICE=esp32-cam-ref  # Gate 2 boot-diff: only THIS device's telemetry proves boot
export AES_STRICT_REGISTRY=1           # Monitor rejects telemetry from unregistered device ids
export AES_ALLOW_VULN_SOURCE=1         # Sol 1 patches main_vulnerable.c (intentional CWE demo) instead of main.c
```

Then reload: `source ~/.zshrc`

### 5 — Start services

```bash
mosquitto -d                       # broker, anonymous port 1883 (Phase 0)
brew services start ollama
ollama pull nomic-embed-text       # REQUIRED — Intel Agent embeds queries via Ollama
```

> **Ollama must be running** whenever the pipeline runs: the Intel Agent embeds every query through it. If it's down, Intel degrades to "no CVE context" rather than crashing, but you lose RAG grounding.

### 6 — Populate CVE database (takes ~10 min)

```bash
source venv/bin/activate
python3 -m rag.ingest_nvd
# Stores ~1000+ documents in ChromaDB from NVD, Exploit-DB, ICS-CERT, Espressif
```

---

## Running (demo runbook — order matters)

```bash
cd ~/aes
source venv/bin/activate
```

**Terminal 1 — Monitor Agent (keep running):**
```bash
python3 -m agents.monitor_agent_mqtt
```
> The monitor is quiet by default — it prints anomalies and "elevated" readings plus a periodic `🟢 fleet quiet` heartbeat, and suppresses routine normal lines so incident blocks stand out.

**Terminal 2 — Simulate device telemetry:**
```bash
# 1) NORMAL mode FIRST — let it run ~1–2 min.
#    This seeds aes_normals.jsonl, the false-positive corpus the learning
#    loop needs before it can certify any skill. (Baseline is pre-seeded,
#    so detection is live from the first reading.)
python3 telemetry_sim.py

# 2) THEN trigger an attack (Ctrl-C the normal sim first, or run a second device):
python3 telemetry_sim.py --attack esp32-cam-01
python3 telemetry_sim.py --attack all
```

> Do **not** start in `--attack` mode on a brand-new baseline. The pre-seeded
> `config/ewma_baseline.json` prevents this, but if you wipe it, run normal
> mode long enough to rebuild a clean baseline first.

When an attack is detected (the monitor logs the incident inline, then a background worker runs the rest so detection never pauses):
1. Incident logged to `aes_incidents.jsonl` (immutable facts hashed to `aes_incidents.hashes`)
2. Intel Agent queries ChromaDB for relevant CVEs
3. Hermes analyzes and returns a verdict — **live**
4. Response Agent routes to Solution 1/2 (Sol 3 — the learning loop — runs from the monitor path); `INVESTIGATE`/low-confidence verdicts are **held for manual review**. Sol 1 validates the patch (Gate 1 + Gate 2) then **holds the physical flash for approval** unless `AES_FLASH_ENFORCE=1`; Sol 2 dry-runs unless `AES_FIREWALL_ENFORCE=1`.
5. Discord `#aes-alerts` receives a structured alert
6. The learning loop proposes tuned detection params → sandbox benchmark → posts to Discord for ✅

**Approve a proposed skill (Solution 3):**
```bash
python3 -m skills.hitl list
python3 -m skills.hitl approve <skill_id>     # injects live; monitor adopts it next reading
python3 -m skills.hitl reject  <skill_id>
```

**Verify the incident log hasn't been tampered with:**
```bash
python3 -c "from agents.monitor_agent import verify_incident_log as v; print(v() or 'OK')"
```

**Full health check:**
```bash
bash test_all.sh
```

### Self-improvement before/after (the core demo)

`--stealth` publishes a throttled, low-and-slow attack (~45% spikes) that sits just under the shipped `0.5` threshold, so the default rule **misses** it. This sequence shows the system learn to catch it:

```bash
python3 telemetry_sim.py                          # 1. normal ~1-2 min (seeds a clean FP corpus)
python3 telemetry_sim.py --stealth esp32-cam-01   # 2. BEFORE: reads ~45% but verdict stays "Normal" — missed
#    Ctrl-C after a few ticks
python3 telemetry_sim.py --attack esp32-cam-01    # 3. loud attack → incident → loop proposes a tighter threshold
#    Ctrl-C once the incident fires
python3 -m skills.hitl approve <skill_id>         # 4. inject the tightened params
python3 telemetry_sim.py --stealth esp32-cam-01   # 5. AFTER: the SAME stealth attack now 🚨 ANOMALY
```

The loud attack (step 3) is what *triggers* the loop — a missed stealth attack can't. After approval, `config/active_detection.json` holds the tightened params and the running monitor adopts them on its next reading. (Incident alerts now report a real detect→respond latency, not 0ms.)

---

## Dashboard (local web app)

A deployable FastAPI dashboard that runs on the **same host as the pipeline** and reads the files it already writes — live fleet tiles, incident feed, the self-improvement chart, and the pending Hermes skills with **Approve / Reject buttons** so you never paste a CLI command. Approve calls the real injector → the running monitor adopts the new params on its next reading.

```bash
pip install fastapi "uvicorn[standard]"            # one-time
uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
# open http://localhost:8000   (keep the monitor running — it writes config/fleet_status.json for the tiles)
```

Localhost-only by default. To let others on the same network view it (projector / phones), bind `--host 0.0.0.0` and open `http://<host-ip>:8000`. It controls live detection, so never expose it to the public internet.

---

## Device Fleet

| Device | Model | Solution | Status |
|---|---|---|---|
| esp32-cam-01 | ESP32-CAM | Track 1 (OTA patch) | Live |
| esp32-cam-02 | ESP32-CAM | Track 1 (OTA patch) | Bench-ready |
| esp32-cam-03 | ESP32-CAM | Track 1 (OTA patch) | Bench-ready |
| tapo-c200-01 | TP-Link Tapo C200 | Track 2 (whitelist) | Live |

---

## RAG Knowledge Base

ChromaDB + nomic-embed-text. Four ingestion sources:

| Source | Content | Size |
|---|---|---|
| NVD | Full CVE corpus with CVSS scores | ~450 entries |
| Exploit-DB | PoC exploit code (used in Gate 2) | ~566 entries |
| ICS-CERT/CISA | Known exploited IoT/OT vulnerabilities | ~74 entries |
| Espressif | ESP32-specific advisories (curated from vendor disclosure) | 16 advisories ✅ |

---

## Validation Gates

**Gate 1 — Semgrep static analysis** — ✅ built (`gates/semgrep/`)
CWE-119 (buffer overflow) · CWE-416 (use-after-free) · CWE-78 (command injection) · CWE-798 (hardcoded credentials, incl. `#define`)

**Gate 2 — two parts:**
- *On-device validate/rollback* (`esp32-cam/main/main.c`) — ✅ built. New firmware self-confirms (WiFi + MQTT handshake) within 30s or auto-reverts to the previous partition.
- *Compile-Boot-Diff harness* (`gates/gate2.py`) — ✅ built and wired into the Solution 1 pipeline. Three stages, each reporting pass/fail/skipped: **structure** (patched source is well-formed, no diff artifacts), **compile** (`idf.py build` of the staged patch — skipped without the ESP-IDF toolchain), **boot-diff** (flash the reference ESP32 set in `GATE2_REFERENCE_PORT`, confirm MQTT boot in 35s, replay recorded attacks and confirm clean fresh telemetry — skipped without hardware). Default = skipped stages don't block; set `AES_GATE2_STRICT=1` (production/demo-day) so anything untested blocks the flash.

---

## Hardware requirements & bench mode

AES runs end-to-end **without any hardware** — every step that needs a physical
device or the ESP-IDF toolchain self-skips with a clear log line, so you can
develop and demo the full pipeline on a laptop. The hardware-gated steps:

- **Solution 1 (OTA patch)** runs the full pipeline today; the `idf.py build` /
  `esptool.py` flash / boot-confirm steps self-skip when no toolchain or device
  is attached. With hardware: plug in the ESP32, set `port` in
  `config/device_registry.json`, and run one real OTA flash.
- **Solution 2 (firewall)** always dry-runs; it writes real firewall rules only
  where `AES_FIREWALL_ENFORCE=1` is set (the gateway). Roll back anytime:
  `python -m openclaw.solution2 release <device_id>`.
- **Gate 2** compile and boot-diff stages self-skip without the ESP-IDF toolchain
  or a reference device (`GATE2_REFERENCE_PORT`). Set `AES_GATE2_STRICT=1` so any
  untested stage blocks the flash.

See [`CHANGELOG.md`](CHANGELOG.md) for the engineering history.

---

## Team

| Name | Role |
|---|---|
| Son Nguyen | AI Infra — Hermes, RAG pipeline, learning loop, Discord bot |
| Duc Vu | Software/Pipeline — OpenClaw integrations, firewall, response routing |
| Vy Tuong Khong | Firmware — ESP32 flashing, Gate 1/2 harnesses, OTA partition |

---

## License

Released under the [MIT License](LICENSE) — © 2026 Son Nguyen and the AES contributors.
