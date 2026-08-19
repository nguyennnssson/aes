# AES ESP32-CAM firmware

ESP-IDF 5.2 firmware for the AES telemetry and firmware-remediation track.

Features:

- raw CPU, memory, packet-rate, and connection telemetry every five seconds;
- ISO-8601 UTC timestamp, per-boot random ID, sequence, and firmware version;
- certificate-verified MQTT TLS with a unique per-device username/password;
- QoS 1 telemetry on `aes/telemetry/<device-id>`;
- dual OTA partitions and 30-second pending-image rollback;
- pending-image acceptance only after three broker-acknowledged telemetry events;
- production defaults for secure boot, anti-rollback, and flash encryption.

Provision credentials in ignored `sdkconfig.secrets` and ignored
`main/srv_cert.crt` with the trusted public gateway CA certificate, then build
with `idf.py build`. Never place the CA private key in the project. Production
builds use:

```text
CONFIG_AES_DEVICE_ID="esp32-cam-01"
CONFIG_AES_FIRMWARE_VERSION="0.1.0"
CONFIG_AES_WIFI_PASSWORD="<unique Wi-Fi secret>"
CONFIG_AES_MQTT_USERNAME="esp32-cam-01"
CONFIG_AES_MQTT_PASSWORD="<unique device secret>"
```

Increment `CONFIG_AES_FIRMWARE_VERSION` for every approved release; Gate 2 and
the deployment approval bind that version to the exact signed artifact.

```bash
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.production.defaults;sdkconfig.secrets" idf.py build
```

See `FLASH.md` for serial installation and `OTA_LIFECYCLE.md` for the distinction
between the current signed serial path and a future genuine network OTA transport.
