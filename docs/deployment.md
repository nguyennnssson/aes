# Install, configure, and deploy

Full setup for development and for a gateway with real devices.

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
AES_INSECURE_DEV_MQTT=1 MQTT_PORT=1883 python scripts/telemetry_sim.py

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

[← Back to README](../README.md)
