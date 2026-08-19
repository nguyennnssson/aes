# AES — Autonomous Edge-Sentinel

AES is a fail-closed IoT incident-response prototype for ESP32 cameras and
gateway-managed closed-firmware cameras. It detects coordinated telemetry
anomalies, retrieves relevant public vulnerability intelligence, asks an LLM for
a structured verdict, and prepares a remediation for explicit operator approval.

AES does **not** claim that an AI verdict is proof of compromise. A physical
action is considered complete only after its independent enforcement evidence
passes. Missing hardware, skipped tests, dry runs, low-confidence intelligence,
and pending approvals all keep an incident open.

## Response tracks

- **Track 1 — firmware remediation:** ESP32-CAM source controlled by the
  operator. Completion requires a static scan, clean compile, authenticated
  reference boot, active attack-harness replay, signed artifact verification,
  hash-bound human approval, hardware security attestation, physical install,
  and authenticated fresh-boot proof.
- **Track 2 — gateway quarantine:** closed-firmware cameras. Completion requires
  registry-pinned IP/MAC identity, gateway dry run, explicit enforcement, and
  verified bidirectional DROP rules.
- **Track 3 — detector tuning:** all enrolled devices. Completion requires an
  independently labelled HMAC-authenticated benchmark corpus, bounded
  parameters, a benchmark pass, hash-bound human approval, and atomic injection.

Track 1 currently performs a **signed serial firmware installation**. It is not
an over-the-air transport. The partition table and on-device rollback lifecycle
support a future genuine OTA transport, but AES does not call `esptool` “OTA.”

## Trust boundaries

```text
ESP32 / camera
  └─ mqtts:8883, per-device username, broker ACL bound to topic
       └─ Monitor (strict registry + bounded payload/schema/queue)
            ├─ Local SQLite vector index + local Ollama embeddings
            ├─ Hermes verdict (untrusted model output, action/track allowlist)
            └─ Response preparation
                 ├─ strict firmware gates → HMAC-bound approval → signed install
                 └─ gateway identity check → dry run → live quarantine → verify
```

The FastAPI dashboard requires `AES_DASHBOARD_TOKEN` for every API request. Its
write endpoints do not use cookie authentication, so a cross-site request cannot
approve a skill without the custom token. The legacy static dashboard constructs
untrusted values as text nodes and loads no third-party JavaScript.

Incident state is a projection backed by an append-only chained event log.
Production requires `AES_AUDIT_HMAC_KEY`; the verifier replays the authenticated
events and compares the resulting state to `aes_incidents.jsonl`.

## Repository map

```text
agents/                 detection, Intel retrieval, Hermes, response state machine
dashboard/              token-protected FastAPI API and local console
esp32-cam/              ESP-IDF firmware, TLS MQTT, dual OTA partitions
gates/                  fail-closed Semgrep and strict hardware validation
openclaw/               gateway quarantine backends
rag/                    embedded SQLite vector index and ingestion
raspberry-pi/           TLS Mosquitto/AP/receiver provisioning
skills/                 bounded detector tuning and authenticated approval
web/                    Next.js operator UI
tests/                   unit and boundary tests
```

Runtime incidents, event logs, telemetry, vector data, patch artifacts, firmware
builds, and secrets are ignored by Git.

## Install

Python 3.11+ and Node.js 22 are supported.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.lock

cd web
npm ci
```

The direct Python requirements are pinned in `requirements.txt`; the universal
resolved dependency set used by CI is `requirements.lock`. Regenerate it with:

```bash
uv pip compile --universal requirements-dev.txt -o requirements.lock
```

Install ESP-IDF and its bundled `esptool`/`espsecure` environment separately on
the reference-hardware workstation. Those platform-specific signing and serial
tools are deliberately excluded from the network-service dependency lock.

The Intel index is embedded SQLite rather than a remotely exposed vector server:

```bash
ollama pull nomic-embed-text
python -m rag.ingest_nvd
```

The ingestion sources are NVD metadata, Exploit-DB catalogue metadata, CISA KEV,
and curated Espressif advisories. AES does not ingest or execute exploit code.
Only results meeting `INTEL_MIN_RELEVANCE` are supplied to Hermes.

## Required secure configuration

Keep all values in an ignored `.env`, a service environment file, or a secret
manager. Do not commit them.

```bash
# MQTT monitor identity
MQTT_HOST=192.168.4.1
MQTT_PORT=8883
MQTT_MONITOR_USERNAME=aes-monitor
MQTT_MONITOR_PASSWORD=<unique password>
MQTT_CA_CERT=/absolute/path/to/aes-ca.crt

# Dashboard and authenticated audit/approval records
AES_DASHBOARD_TOKEN=<random token>
AES_AUDIT_HMAC_KEY=<at least 32 random characters>
AES_DEPLOY_APPROVAL_KEY=<at least 32 random characters>
AES_SKILL_APPROVAL_KEY=<at least 32 random characters>
AES_BENCHMARK_HMAC_KEY=<at least 32 random characters>

# Production guardrails
AES_PRODUCTION=1

# OpenAI Responses API backend (independently configurable roles)
HERMES_BACKEND=openai
HERMES_MODEL=gpt-5.6-sol
HERMES_CODE_MODEL=gpt-5.6-sol
```

`AES_INSECURE_DEV_MQTT=1` is an explicit loopback-only development escape hatch.
Secure MQTT is the default. Unknown device IDs are rejected by default;
`AES_ALLOW_UNREGISTERED_DEVICES=1` is development-only.

The Codex CLI backend runs in an isolated temporary workspace with a scrubbed
environment. It is disabled when `AES_PRODUCTION=1` unless an operator explicitly
sets `AES_ALLOW_AGENTIC_LLM=1` after reviewing that risk. The non-agentic OpenAI
API backend is the recommended production backend.

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

The installer refuses the repository passphrase placeholder, configures TLS on
port 8883, disables anonymous access, installs topic ACLs and static leases, and
runs the telemetry receiver with systemd filesystem restrictions. Passwords must
be unique, 16 or more characters, and use the installer's shell-safe character
set. The gateway certificate must chain to the supplied CA, match its private key,
and contain an IP subjectAltName for `192.168.4.1`.

Closed-firmware devices also need matching `ip` and `mac` fields in
`config/device_registry.json`. Quarantine is refused if the gateway's neighbor
table does not match the pinned identity. Set `GATEWAY_SSH` when the response
process is not itself running on the forwarding gateway.

## ESP32 provisioning

Put build secrets in ignored `esp32-cam/sdkconfig.secrets`:

```text
CONFIG_AES_DEVICE_ID="esp32-cam-01"
CONFIG_AES_FIRMWARE_VERSION="0.1.0"
CONFIG_AES_WIFI_PASSWORD="<AP passphrase>"
CONFIG_AES_MQTT_USERNAME="esp32-cam-01"
CONFIG_AES_MQTT_PASSWORD="<unique device password>"
CONFIG_AES_MQTT_BROKER_URI="mqtts://192.168.4.1:8883"
```

Provision ignored `esp32-cam/main/srv_cert.crt` with the trusted public gateway
CA certificate for the build; never copy the CA private key. For production,
build with the production security profile
and external signing/encryption keys:

```bash
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.production.defaults;\
sdkconfig.secrets" idf.py build
```

Secure-boot and flash-encryption eFuse provisioning is irreversible; follow the
Espressif production guide and preserve recovery keys offline. AES additionally
requires `AES_HARDWARE_SECURITY_VERIFIED=1` and verifies the firmware signature
with `AES_FIRMWARE_PUBLIC_KEY` before a physical installation.

## Run

```bash
python -m agents.monitor_agent_mqtt

# In a separate terminal, development broker only:
AES_INSECURE_DEV_MQTT=1 MQTT_PORT=1883 python telemetry_sim.py

AES_DASHBOARD_TOKEN=<token> uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
```

Do not bind the dashboard to a LAN address unless TLS is terminated in front of
it and `AES_DASHBOARD_HOSTS` / `AES_DASHBOARD_ORIGINS` explicitly name that host.

## Firmware remediation lifecycle

Gate 2 is strict by default. A deployable run requires all of:

- `idf.py` and a clean staged build;
- `GATE2_REFERENCE_PORT` and `GATE2_REFERENCE_DEVICE`;
- an executable `GATE2_ATTACK_HARNESS` that accepts `--device` and `--port`;
- authenticated MQTT monitor credentials and a private CA;
- a labelled historical attack regression corpus;
- clean authenticated telemetry during the active replay.

If any item is absent, Gate 2 rejects the patch. `--allow-skips` is only for a
diagnostic invocation and response-agent code will not accept that result.

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
hash, patched-source hash, patch hash, firmware hash, and artifact path. Source,
version, or artifact drift invalidates the approval. Rejected artifacts are
moved out of `pending/`; a successful install moves them to `deployed/`.

## Detector tuning corpus

Detector-created incidents and device-declared “normal” readings are not
independent ground truth. They cannot certify a tuning proposal. An operator must
review and sign samples with `scripts/label_sample.py` and
`AES_BENCHMARK_HMAC_KEY`. A benchmark requires at least one authenticated ATTACK
and NORMAL sample, plus the detection/false-positive thresholds in
`skills/sandbox.py`.

Skill approval additionally requires `AES_SKILL_APPROVAL_KEY`; changing params or
benchmark data after approval invalidates injection.

## Verification

```bash
pytest tests -q
python tests/diagnostic.py
python -c \
  "from agents.monitor_agent import verify_incident_log as v; print(v() or 'OK')"

cd web
npm audit --omit=dev --audit-level=high
npm run typecheck
npm run build
```

CI runs the locked Python dependency audit, unit and pipeline tests, the web audit,
typecheck/build, and an ESP-IDF firmware build. See `SECURITY.md` for private
vulnerability reporting.

## License

MIT — © 2026 Son Nguyen and AES contributors.
