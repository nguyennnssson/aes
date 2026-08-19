# ESP32 OTA validation lifecycle

The firmware contains a dual-OTA partition table and ESP-IDF rollback logic for a
future genuine network OTA transport. The AES host currently performs an explicit
signed **serial installation**; it does not pretend that `esptool` is OTA.

When another trusted component writes a signed image to the inactive OTA slot and
selects it for boot, ESP-IDF transitions it to `ESP_OTA_IMG_PENDING_VERIFY`.
`ota_watchdog_task()` then gives the candidate 30 seconds to demonstrate health.

Health requires all of the following:

1. Wi-Fi association and valid NTP time.
2. A certificate-verified `mqtts://` connection on port 8883.
3. Per-device username/password authentication.
4. Three QoS 1 telemetry publications acknowledged by the broker.

Only after the third acknowledgement does `validate_and_confirm_app()` call
`esp_ota_mark_app_valid_cancel_rollback()`. A connection event by itself is not
accepted as proof. If the image remains pending after 30 seconds, the firmware
calls `esp_ota_mark_app_invalid_rollback_and_reboot()`.

Direct serial installation does not create `PENDING_VERIFY`; therefore this
rollback state machine is not a recovery guarantee for the current host-side
deployment path. The host instead requires a signed artifact, secure-boot/flash-
encryption attestation, an authenticated reference-device test, explicit
hash-bound approval, and authenticated post-install boot evidence.

The broker ACL restricts a device username to `aes/telemetry/<username>`. Firmware
requires `CONFIG_AES_MQTT_USERNAME == CONFIG_AES_DEVICE_ID`, and ignored local
`srv_cert.crt` must be the trusted public CA certificate that issued the broker
certificate. The CA private key must never be copied into firmware or Git.
