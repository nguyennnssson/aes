# AES — Autonomous Edge-Sentinel

AES watches IoT cameras for coordinated telemetry anomalies, asks an LLM to
classify each incident against retrieved public vulnerability data, and prepares
a remediation. Firmware fixes and detector changes are held for human approval;
network quarantine of closed-firmware cameras can be enforced automatically once
an operator enables it.

AES started as a team project at the ClawComp hackathon and was developed
further afterwards. It is a prototype: an AI verdict is never treated as proof of
compromise, and missing hardware, skipped gates, dry runs, low confidence, or
pending approvals all keep an incident open.

## Architecture

```text
ESP32-CAM firmware (C, ESP-IDF 5.2)       closed-firmware camera (e.g. TP-Link Tapo C200)
  telemetry JSON every 5 s:                 no on-device agent; telemetry for these
  cpu, memory, packet rate, connections     devices in this repo comes from telemetry_sim.py
        │  MQTT over TLS :8883, per-device credentials + topic ACL
        ▼
Mosquitto broker (raspberry-pi/)
        ▼
Monitor agent          agents/monitor_agent_mqtt.py, agents/monitor_agent.py
  per-device EWMA baseline (alpha 0.1, 12-sample warm-up); anomaly when
  >= simultaneous_threshold metrics deviate >= deviation_threshold (defaults 2 and 0.5)
        ▼
Intel agent            agents/intel_agent.py
  local SQLite vector index → CVE chunks above INTEL_MIN_RELEVANCE (top 5)
        ▼
Hermes                 agents/hermes.py + agents/llm_client.py
  reasoning chain (Claude ⇄ Codex/OpenAI) → JSON verdict {action, cve_id, confidence}
  action allowlisted and pinned to the device's registry track; confidence < 0.5 → manual review
        ▼
Response agent         agents/response_agent.py
  ├─ Track 1 (open firmware): code chain writes a C patch → patch policy → Gate 1 Semgrep
  │    → Gate 2 compile / reference boot / attack replay → HELD for hash-bound human approval
  │    → signed serial install (esptool) → authenticated fresh-boot proof over MQTT
  ├─ Track 2 (closed firmware): openclaw/ gateway quarantine → IP/MAC identity check → dry run
  │    → enforced automatically only when AES_FIREWALL_ENFORCE=1 → DROP rules verified
  └─ Track 3 (all devices): Hermes proposes new detection thresholds → sandbox 80% / 10% gate
       → human approval → config/active_detection.json (monitor adopts on next reading)
        ▼
Discord #aes-alerts webhook (discord/) and token-protected FastAPI dashboard (dashboard/)
```

Track 1 installs firmware over USB serial with `esptool`. The dual-partition
layout and rollback logic in the firmware support a future over-the-air
transport, but AES does not perform OTA updates today.

## Model providers

"Hermes" (`agents/hermes.py`) and "OpenClaw" (`openclaw/`) are this project's
names for its reasoning and execution layers. They are plain Python modules and
do not use the external Hermes Agent or OpenClaw frameworks.

`agents/llm_client.py` implements four backends behind one interface:

| Backend | How it authenticates | Model setting |
|---|---|---|
| `claude` | Anthropic Messages API, `ANTHROPIC_API_KEY` | `HERMES_CLAUDE_MODEL` (default `claude-opus-5-5`) |
| `claude-cli` | Claude Code CLI login (`claude -p --safe-mode`, all tools disabled) | `HERMES_CLAUDE_CLI_MODEL` (default: CLI default) |
| `openai` | OpenAI Responses API, `OPENAI_API_KEY` | `HERMES_MODEL` / `HERMES_CODE_MODEL` (default `gpt-5.6-sol`) |
| `codex` | Codex CLI login (`codex exec`, read-only sandbox) | `HERMES_CLI_MODEL` (default: CLI default) |

Hermes has two roles, and each role has an ordered backend chain:

- `HERMES_BACKEND` — reasoning: incident verdicts, packet-window
  classification, detector-tuning proposals.
- `HERMES_CODE_BACKEND` — firmware patch generation.

```bash
HERMES_BACKEND=claude,codex        # Claude classifies and plans; Codex is the backup
HERMES_CODE_BACKEND=codex,claude   # Codex writes patches; Claude is the backup
```

With both unset (or `auto`), every configured backend is used in this order.
Reasoning tries `claude`, `claude-cli`, `openai`, then `codex`. Patch generation
tries `openai`, `codex`, `claude`, then `claude-cli`. A backend counts as
configured when its API key is set or its CLI is on `PATH`.

**How fallback is triggered.** The chain sends the request to the first backend.
The request moves to the next backend when the current one raises one of these:
a missing CLI or key, a non-zero CLI exit, a timeout (30 s for API verdicts,
60 s for patches, at least 120 s for CLIs), empty output, or any provider SDK
error (connection, authentication, rate limit, server error). A reply that is
not valid JSON does not trigger failover; it becomes a held `INVESTIGATE`
verdict with confidence 0. When every backend in the chain fails, Hermes calls
the local offline fallback in `agents/fallback.py`. That fallback is Llama 3 8B
(`llama3:8b-instruct-q4_K_M`) served by Ollama. Its confidence is capped at
0.49, so its verdicts always go to manual review, and it cannot generate patches.

Every verdict stores the backend that produced it in `verdict.backend` (for
example `claude-cli:opus` or `ollama:llama3:8b-instruct-q4_K_M`). Track 1 patch
manifests store it in `generated_by`.

Check every configured backend with one live prompt: `python scripts/check_backends.py`.

With `AES_PRODUCTION=1`, the CLI backends (`claude-cli`, `codex`) are skipped
because they drive agentic tools. Set `AES_ALLOW_AGENTIC_LLM=1` only after a
risk review. Both CLIs run in an empty temporary directory with a scrubbed
environment, so application secrets from `.env` are never passed to them. They
also ignore the operator's personal CLI setup: Codex runs with
`--ignore-user-config --ignore-rules`, and Claude Code runs with `--safe-mode`
(no hooks, plugins, skills, MCP servers, or CLAUDE.md). A Claude Code version
without `--safe-mode` is refused, and the request moves to the next backend.

## Vulnerability index

```bash
ollama pull nomic-embed-text
python -m rag.ingest_nvd
```

`rag/ingest_nvd.py` builds an embedded SQLite vector index at
`AES_INTEL_DB` (default `./data/aes_intel.sqlite3`). It uses `nomic-embed-text`
embeddings from a local Ollama server and cosine similarity. The index is not
committed; each machine builds its own. Sources:

| Source | What is ingested | Limit in the code |
|---|---|---|
| NVD CVE API 2.0 | CVE description, CVSS, CWE | first 100 results for each of 6 keyword searches (≤ 600) |
| Exploit-DB `files_exploits.csv` | catalogue metadata only, no exploit code | rows matching 7 IoT keywords |
| CISA Known Exploited Vulnerabilities | KEV entries matching IoT keywords | stored with the source label `ICS-CERT` |
| Espressif advisories | curated snapshot in `rag/espressif_advisories.json` | 16 advisories |

Records are de-duplicated by ID. The total depends on what the live feeds
return on the day of ingestion, and the script prints `DB total` when it
finishes. Only chunks with relevance ≥ `INTEL_MIN_RELEVANCE` (default 0.65) are
sent to Hermes, inside a fenced block marked as untrusted data.

## Detector-tuning gate (Track 3)

After an incident, Hermes proposes new values for the two detection parameters,
`deviation_threshold` (clamped to 0.30–5.0) and `simultaneous_threshold`
(1–4). It does not write executable code. `skills/sandbox.py` replays labelled
samples through the same `evaluate_detection()` function the live monitor uses:

- **detection rate** = flagged ATTACK samples ÷ ATTACK samples, which must be ≥ 0.80;
- **false-positive rate** = flagged NORMAL samples ÷ NORMAL samples, which must be ≤ 0.10;
- at least one ATTACK and one NORMAL sample are required.

Only samples signed by an operator count. Detector-created incidents are not
independent ground truth, so `scripts/label_sample.py` adds an HMAC label with
`AES_BENCHMARK_HMAC_KEY`. Point the gate at the signed corpora with
`AES_BENCHMARK_ATTACKS` and `AES_BENCHMARK_NORMALS`.

Approval happens in one of two places:

- CLI: `python -m skills.hitl approve <skill_id> <approver>` (`list` / `reject` also available);
- dashboard: `POST /api/approve/{skill_id}` with `AES_DASHBOARD_TOKEN`.

Both re-run the benchmark immediately before approving. The approval is
HMAC-signed with `AES_SKILL_APPROVAL_KEY` over the parameters and benchmark,
and `skills/inject.py` refuses a skill whose signature no longer matches. The
Discord webhook announces proposals; approving with a Discord reaction is not
implemented.

Reproduce a gate result from signed corpora:

```bash
export AES_BENCHMARK_HMAC_KEY=<32+ chars>
python scripts/label_sample.py ATTACK sample.json attack_labels.jsonl --reviewer <you>
python scripts/label_sample.py NORMAL normal.json normal_labels.jsonl --reviewer <you>
python -m skills.sandbox --attacks attack_labels.jsonl --normals normal_labels.jsonl \
    --deviation-threshold 0.35 --simultaneous-threshold 2 --json   # exit 0 = PASS
```

No signed benchmark corpus is committed, so the repository contains no gate
results to reproduce. `tests/test_sandbox.py` runs this label-then-benchmark
flow on a small synthetic corpus.

## Hardware

- **Tested:** the ESP32-CAM firmware in `esp32-cam/` was built with ESP-IDF
  5.2.7 and flashed over USB to an ESP32-CAM board (ESP32-D0WD-V3, revision
  3.1). Its telemetry was streamed into the pipeline through a USB-serial bridge
  to the local broker. CI builds the firmware on every push to `main`
  and every pull request (`.github/workflows/esp32-build.yml`).
- **Not yet done on hardware:** the attack scenarios in this repo use
  `telemetry_sim.py`. A Gate 2 run against a reference board and an end-to-end
  remediation install have not been completed. The Tapo C200 quarantine path has
  been exercised only as a dry run (Windows `netsh` backend).
- `scripts/live_demo.py` and the web UI's demo mode (`web/lib/mock.ts`) produce
  illustrative sample data, including the dashboard's 80→95% detection curve and
  312 ms latency. The web UI marks its demo mode "PROTOTYPE · SAMPLE DATA". These
  numbers are not measurements.

## Install

Python 3.11+ and Node.js 22 are supported.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.lock
cp .env.example .env               # then choose backends and fill in keys

cd web
npm ci
```

The direct Python requirements are pinned in `requirements.txt`. The universal
resolved set used by CI is `requirements.lock`; regenerate it with:

```bash
uv pip compile --universal requirements-dev.txt -o requirements.lock
```

Optional tools, installed separately:

- Claude Code (`claude`) and/or the Codex CLI (`codex`) for the CLI backends;
- Ollama for embeddings and the Llama 3 fallback;
- Semgrep in `.tools/semgrep-venv` for Gate 1;
- ESP-IDF with `esptool` / `espsecure` on the hardware workstation.

## Configuration

Every setting is documented in `.env.example`. Keep values in the ignored
`.env`, a service environment file, or a secret manager. The minimum secure set:

```bash
MQTT_HOST=192.168.4.1
MQTT_PORT=8883
MQTT_MONITOR_USERNAME=aes-monitor
MQTT_MONITOR_PASSWORD=<unique password>
MQTT_CA_CERT=/absolute/path/to/aes-ca.crt

AES_DASHBOARD_TOKEN=<random token>
AES_AUDIT_HMAC_KEY=<at least 32 random characters>
AES_DEPLOY_APPROVAL_KEY=<at least 32 random characters>
AES_SKILL_APPROVAL_KEY=<at least 32 random characters>
AES_BENCHMARK_HMAC_KEY=<at least 32 random characters>
AES_PRODUCTION=1
```

`AES_INSECURE_DEV_MQTT=1` is a loopback-only development escape hatch. Unknown
device IDs are rejected unless `AES_ALLOW_UNREGISTERED_DEVICES=1`
(development only).

## Run

```bash
python -m agents.monitor_agent_mqtt

# In a separate terminal, development broker only:
AES_INSECURE_DEV_MQTT=1 MQTT_PORT=1883 python telemetry_sim.py

AES_DASHBOARD_TOKEN=<token> uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
```

Do not bind the dashboard to a LAN address unless TLS is terminated in front of
it and `AES_DASHBOARD_HOSTS` / `AES_DASHBOARD_ORIGINS` name that host.

## Firmware remediation lifecycle (Track 1)

Gate 2 is strict by default. A deployable run requires all of the following:

- `idf.py` and a clean staged build;
- `GATE2_REFERENCE_PORT` and `GATE2_REFERENCE_DEVICE`;
- an executable `GATE2_ATTACK_HARNESS` that accepts `--device` and `--port`;
- authenticated MQTT monitor credentials and a private CA;
- a labelled historical attack regression corpus;
- clean authenticated telemetry during the active replay.

If any item is missing, Gate 2 rejects the patch.

After validation:

```bash
AES_DEPLOY_APPROVAL_KEY=<key> \
  python -m agents.response_agent approve <incident-id> <approver>

AES_FLASH_ENFORCE=1 \
AES_DEPLOY_APPROVAL_KEY=<same-key> \
AES_FIRMWARE_PUBLIC_KEY=/path/to/public-key.pem \
AES_HARDWARE_SECURITY_VERIFIED=1 \
  python -m agents.response_agent flash <incident-id>
```

Approval signs the incident ID, device ID, firmware version, original source
hash, patched-source hash, patch hash, firmware hash, and artifact path. Any
drift invalidates the approval.

## Raspberry Pi gateway

Run `raspberry-pi/setup_ap.sh` as root with these provisioning inputs:

- `AES_AP_PASSPHRASE`
- `AES_MQTT_MONITOR_PASSWORD`
- `AES_MQTT_RECEIVER_PASSWORD`
- `AES_MQTT_DEVICE_CREDENTIALS_FILE` (`device-id:unique-password` per line)
- `AES_DEVICE_LEASES_FILE` (`mac,192.168.4.10-50,device-id` per line)
- `AES_MQTT_CA_CERT_SOURCE`, `AES_MQTT_SERVER_CERT_SOURCE`, and
  `AES_MQTT_SERVER_KEY_SOURCE`
- optional `AES_SERVICE_USER` (defaults to `pi` and must already exist)

The installer configures TLS on port 8883, disables anonymous access, and
installs topic ACLs and static leases. It also runs the telemetry receiver under
systemd filesystem restrictions. Closed-firmware devices need matching `ip` and
`mac` fields in `config/device_registry.json`; quarantine is refused if the
gateway's neighbor table does not match. Set `GATEWAY_SSH` when the response
process does not run on the gateway itself.

## ESP32 provisioning

Put build secrets in the ignored `esp32-cam/sdkconfig.secrets`:

```text
CONFIG_AES_DEVICE_ID="esp32-cam-01"
CONFIG_AES_FIRMWARE_VERSION="0.1.0"
CONFIG_AES_WIFI_PASSWORD="<AP passphrase>"
CONFIG_AES_MQTT_USERNAME="esp32-cam-01"
CONFIG_AES_MQTT_PASSWORD="<unique device password>"
CONFIG_AES_MQTT_BROKER_URI="mqtts://192.168.4.1:8883"
```

Provision the ignored `esp32-cam/main/srv_cert.crt` with the gateway CA's public
certificate. For production, build with the production security profile:

```bash
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.production.defaults;\
sdkconfig.secrets" idf.py build
```

Secure-boot and flash-encryption eFuse provisioning is irreversible; follow the
Espressif production guide.

## Verification

```bash
pytest tests -q
python tests/diagnostic.py
python -c \
  "from agents.monitor_agent import verify_incident_log as v; print(v() or 'OK')"

cd web && npm audit --omit=dev --audit-level=high && npm run typecheck && npm run build
```

CI runs the locked Python dependency audit, unit and pipeline tests, the web
audit, typecheck and build, and an ESP-IDF firmware build.

## Known limitations

- Gate 1 rejects the demo source `esp32-cam/main/main_vulnerable.c`. Semgrep's C
  parser cannot parse its `"aes/telemetry/" DEVICE_ID` string-macro
  concatenation, and `--strict` fails closed. The production `main.c` scans cleanly.
- Closed-firmware cameras have no telemetry collector in this repo.
- The `ICS-CERT` source label refers to the CISA KEV feed, not ICS-CERT advisories.

## Repository map

```text
agents/        monitor, Intel retrieval, Hermes, model backends, response state machine
dashboard/     token-protected FastAPI API and local console
discord/       #aes-alerts webhook posts
esp32-cam/     ESP-IDF firmware (C): telemetry, TLS MQTT, dual OTA partitions + rollback
gates/         Gate 1 (Semgrep rules) and Gate 2 (compile / boot / replay)
openclaw/      gateway quarantine backends (iptables, pf, netsh)
rag/           vulnerability ingestion and the SQLite vector index
raspberry-pi/  TLS Mosquitto / access point / receiver provisioning
skills/        detector-tuning sandbox, signed approval, injection
web/           Next.js operator UI
tests/         unit and boundary tests
```

## Team

Team roles at ClawComp:

- Son Nguyen — AI infrastructure: Hermes, model backends, RAG, learning loop, monitor, docs.
- Duc Vu — software and pipeline: OpenClaw gateway quarantine and response routing.
- Vy Tuong Khong — firmware: the ESP32-CAM dual-OTA firmware and the Gate 1 / Gate 2 harnesses.

## License

MIT — © 2026 Son Nguyen and AES contributors.
