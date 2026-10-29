# Architecture

Detailed data flow, file by file. The README has the short version.

```text
ESP32-CAM firmware (C, ESP-IDF 5.2)       closed-firmware camera (e.g. TP-Link Tapo C200)
  telemetry JSON every 5 s:                 no on-device agent; telemetry for these
  cpu, memory, packet rate, connections     devices in this repo comes from scripts/telemetry_sim.py
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

[← Back to README](../README.md)
