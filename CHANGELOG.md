# Changelog

Engineering history for AES — Autonomous Edge-Sentinel. Newest first.

## Reasoning backend → OpenAI Responses API

- Hermes' OpenAI backend uses the Responses API. Reasoning calls and firmware
  patch generation default to `gpt-5.6-sol`, with independent environment
  settings so each role can be evaluated and changed separately.
- Two swappable backends (`agents/llm_client.py`): `openai` (OpenAI SDK +
  `OPENAI_API_KEY`) and `codex` (the `codex` CLI, ChatGPT subscription auth).
  Model settings can be changed without code changes.
- Offline fallback to a local Llama 3 (Ollama) if the OpenAI backend is
  unreachable — the monitor never crashes on a backend outage.

## Hardening pass — pipeline correctness & safety

- **Solution 1 flashes the PATCHED firmware, not the original.** The ESP-IDF
  project compiles only `main.c`, so an earlier build/flash could ship the
  unpatched binary while marking the incident RESOLVED. `handle_solution_1` now
  stages a project copy with the patched text written *as* `main.c` (mirroring
  Gate 2) and flashes that binary — reusing Gate 2's `verified_firmware.bin`
  when available.
- **The incident pipeline runs off the MQTT callback thread.** Intel + Hermes +
  gates + flash previously ran inline on paho's single network thread, blinding
  the whole fleet during any remediation. It now hands off to a background
  worker; detection for other devices never pauses.
- **Physical actions are HITL-gated.** Flashing model-generated C requires
  `AES_FLASH_ENFORCE=1`; by default a validated patch is held at
  `stage=awaiting_flash_approval` and deployed with
  `AES_FLASH_ENFORCE=1 python -m agents.response_agent flash <incident_id>`.
  Hermes' `action` is allowlisted and `confidence` clamped, retrieved CVE
  context is fenced as untrusted (prompt-injection defense-in-depth), and
  offline-fallback verdicts are capped below the auto-execute threshold.
- **Gate 1 feedback drives patch retries.** A rejected patch is regenerated with
  the Semgrep findings in the prompt, and `respond()` no longer re-runs the whole
  track-1 handler 3× at full model cost.
- **Spoofed telemetry is rejected** (payload `device_id` must match the topic
  id), the skill sandbox samples the elevated-but-benign band and excludes
  fabricated demo incidents, boot-proof is filtered to the reference device, and
  the hash ledger detects deletions as well as edits.
- **Robustness/hygiene:** live detection params are validated + clamped on load
  (a corrupt file can't kill detection), the baseline write is atomic +
  throttled, dependencies are version-bounded, and a `pytest` unit suite
  (`tests/`, 41 tests) covers the diff-applier, detection core, sandbox, verdict
  hardening, and log verifier — wired into CI.

## Finalization pass

- **paho-mqtt 2.x compatibility** — all client construction goes through
  `agents/mqtt_compat.py` (works on 1.x and 2.x, callbacks unchanged).
- **Solution 2 is real** — `openclaw/solution2.py` + `openclaw/firewall.py`: IP
  resolution from the registry, input validation (no shell, `ipaddress`-parsed
  IPs, sanitized rule names), mandatory dry-run, opt-in enforcement
  (`AES_FIREWALL_ENFORCE=1`), post-write verification with automatic rollback on
  failure, and an append-only audit trail in `outputs/firewall/actions.jsonl`.
- **Gate 2 built and wired** — `gates/gate2.py` (structure / compile / boot-diff),
  invoked between Gate 1 and the firmware build in `handle_solution_1()`.
  `AES_GATE2_STRICT=1` makes skipped stages block deployment.
- **Firmware credentials out of source** — `WIFI_SSID`/`WIFI_PASS`/`DEVICE_ID`/
  broker URI moved to Kconfig (`main/Kconfig.projbuild`); password default is
  empty and set per build via `menuconfig` or a gitignored `sdkconfig.secrets`.
  `main.c` passes Gate 1's CWE-798 rule.
- **Windows portability** — Gate 1 subprocess uses `sys.executable`, gate output
  prints UTF-8 on cp1252 consoles, and the semgrep venv entry-point shims are
  regenerated on relocation.
- **`datetime.utcnow()` deprecations removed** (Python 3.12+) in the incident logger.

## Core capabilities

- **Solution 3 actually changes detection** — a live param file the monitor polls
  by mtime (was previously a no-op).
- **Sandbox benchmark measures false positives** against a real normal corpus — a
  "flag-everything" rule now fails.
- **Incident pipeline is exception-safe** (try/finally) with a real per-device
  cooldown; incident latency is measured detect→respond.
- **Anti-poisoning:** the EWMA baseline (and FP corpus) freeze only when 2+
  metrics are jointly elevated (the stealth signature), so normal traffic isn't
  frozen in as "elevated" while a low-and-slow attack can't drift "normal" upward.
- **Sustained / low-and-slow detection** (`monitor_agent.py`): a stateful guard
  fires when 2+ metrics stay warm (≥35% over baseline) across a 6-reading window —
  catching throttled attacks held just under the instantaneous spike threshold.
  Verified: 0 false positives on a 220-sample normal stream; a +41%/+44%
  low-and-slow attack caught in 6 readings.
- **Espressif RAG source** (`rag/ingest_espressif()`): a curated 16-advisory
  ESP32/ESP-IDF corpus (OTA anti-rollback and secure-boot advisories) feeds the
  Intel Agent, `ESP-`-namespaced so it coexists with NVD entries.
- **Tamper-evident incident ledger** — immutable facts hashed to
  `aes_incidents.hashes`; `verify_incident_log()` detects edits and deletions.
