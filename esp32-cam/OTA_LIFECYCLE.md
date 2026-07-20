# AES ESP32-CAM OTA State Machine & Rollback Lifecycle

This describes the OTA validation flow as actually implemented in
[`main/main.c`](main/main.c) (`validate_and_confirm_app()` + `ota_watchdog_task()`).
The transport is **plain MQTT** — see the Security note at the end.

## 1. State Transitions

- **ESP_OTA_IMG_NEW**: A new firmware binary is written to the inactive OTA slot
  (`ota_1`) over WiFi. The bootloader is configured to boot it on the next reset.
- **ESP_OTA_IMG_PENDING_VERIFY**: The chip boots into the new firmware. A 30-second
  FreeRTOS watchdog (`ota_watchdog_task`) starts its validation window.
- **ESP_OTA_IMG_VALID**: Applied as soon as the device establishes its MQTT
  connection within the 30-second window. On `MQTT_EVENT_CONNECTED`,
  `validate_and_confirm_app()` checks the running partition; if it is in
  `PENDING_VERIFY` it calls `esp_ota_mark_app_valid_cancel_rollback()`, which
  cancels the pending rollback and accepts the firmware permanently.
  - Establishing the MQTT connection requires WiFi to be associated first, so a
    successful connect implies both WiFi **and** broker reachability.
  - Broker: `mqtt://192.168.4.1:1883` (plain MQTT, anonymous — matches the Pi's
    `raspberry-pi/mosquitto.conf`).
- **ESP_OTA_IMG_INVALID (Rollback)**: If the 30-second timer expires while the
  partition is still `PENDING_VERIFY` (no MQTT connection — WiFi/broker down or a
  hang), `ota_watchdog_task` calls `esp_ota_mark_app_invalid_rollback_and_reboot()`.
  The device restarts and the bootloader falls back to the previous slot (`ota_0`).

> **Note:** A direct `idf.py flash` puts the partition in factory/`ota_0` state, **not**
> `PENDING_VERIFY`, so the watchdog is a no-op after a wired flash. Rollback only
> happens after a genuine over-the-air update. See [FLASH.md](FLASH.md).

## 2. Hard Reset Recovery Test Vector

- Force-flash a damaged/crashing image to `ota_1` and boot it.
- Expected: the image fails to reach `MQTT_EVENT_CONNECTED` within 30 s (or crashes
  on boot); the watchdog marks it invalid and reboots, and the bootloader falls
  back to `ota_0` within 2 boot cycles.

## Security note — transport is plain MQTT, not TLS

Validation currently keys off the **MQTT connection being established**, over plain
MQTT on port 1883. There is no TLS in the live pipeline: the firmware's
`esp_mqtt_client_config_t` uses a `mqtt://` URI, and the Pi broker listens on 1883
without certificates.

`main/srv_cert.crt` is embedded into the binary (`EMBED_TXTFILES` in
[`main/CMakeLists.txt`](main/CMakeLists.txt)) as a placeholder for a **planned**
hardening step: switching to `mqtts://192.168.4.1:8883`, wiring the cert into
`mqtt_cfg.broker.verification.certificate`, and (optionally) gating validation on the
first telemetry publish instead of on connect. That work is **not yet done** — until
it is, the embedded cert is unused and the broker must also be reconfigured for TLS.
