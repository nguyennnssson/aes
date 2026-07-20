# AES ESP32-CAM Flashing & Monitoring Guide

## Hardware Setup

Board: **Aideepen ESP32-CAM-MB (Type-C)** with OV2640 + CH340G USB-to-serial  
IDE: **ESP-IDF 5.2** on Windows (ASUS Vivobook)

---

## Why the Monitor Triggers Bootloader Mode — Root Cause

The ESP32-CAM-MB uses a two-transistor **auto-program circuit** that wires the CH340G control lines directly to the ESP32 boot-mode pins:

```
CH340G DTR  ──▶  ESP32 GPIO0  (LOW = bootloader mode)
CH340G RTS  ──▶  ESP32 EN     (pulse LOW → HIGH = chip reset)
```

When **any** serial application (idf.py monitor, PuTTY, Arduino IDE, Device Manager) opens the COM port, the Windows CH340G driver **asserts DTR and RTS** by default. This executes the exact same boot-mode sequence esptool uses for flashing:

1. GPIO0 pulled LOW → ESP32 enters bootloader mode on next reset
2. EN pulsed LOW → HIGH → chip resets
3. Result: ESP32 boots into **ROM bootloader** instead of running the app

Running `idf.py flash monitor` back-to-back makes this worse — after flash completes, the monitor sub-command opens the port fresh, triggers the reset again, and you see another bootloader start instead of your app output.

**The fix: always pass `--no-reset` when you only want to monitor.**

---

## Correct Procedure

### Step 1 — Identify the COM Port

1. Plug the ESP32-CAM-MB into a USB 3.x port on the ASUS Vivobook.
2. Press `Win + X` → Device Manager → Ports (COM & LPT).
3. Note the port, e.g. `USB-SERIAL CH340 (COM3)`.

---

### Step 2 — Flash Only (do NOT run monitor yet)

Open **ESP-IDF 5.2 CMD** at the `esp32-cam/` project directory:

```cmd
idf.py -p COM3 flash
```

esptool will:
- Hold GPIO0 LOW (bootloader mode)
- Pulse EN to reset into bootloader
- Write firmware over UART
- Release GPIO0 HIGH + pulse EN → ESP32 **boots into the new app**

After this command exits, the chip is already running. Do **not** open any other serial application yet.

---

### Step 3 — Monitor WITHOUT Triggering a Reset

```cmd
idf.py -p COM3 monitor --no-reset
```

The `--no-reset` flag tells the monitor **not to toggle DTR/RTS** when it opens the port. You will see live log output from the running firmware immediately — no bootloader re-entry.

Expected boot sequence in the monitor:
```
I (xxx) AES_GATE2: AES Firmware Booting...
I (xxx) AES_GATE2: Analyzing Running Partition: ota_0
W (xxx) AES_GATE2: Safety Watchdog Started. 30-second validation window open...
I (xxx) AES_GATE2: Network Link Established.
I (xxx) AES_GATE2: MQTT Connected.
I (xxx) AES_GATE2: SUCCESS! Safety validation passed. Rollback canceled. Firmware signed off!
I (xxx) AES_GATE2: Telemetry stream: {"device_id":"esp32-cam-02","cpu_percent":15.0,...}
```

Exit monitor: **Ctrl + ]**

---

### Step 4 — Combined (Flash + Monitor) — Single Command

Use the PowerShell helper that handles the sequence safely:

```powershell
.\flash.ps1 -Port COM3
```

See [flash.ps1](flash.ps1) for the script.

Or manually in sequence:

```cmd
idf.py -p COM3 flash && idf.py -p COM3 monitor --no-reset
```

---

## OTA Watchdog — 30-Second Window

The firmware runs a watchdog that starts on every boot:

- **If** the OTA partition state is `PENDING_VERIFY` (only true after an over-the-air update, NOT after a direct `idf.py flash`): the chip must connect to WiFi + MQTT within 30 seconds or it rolls back to the previous OTA partition.
- **If** flashed directly with `idf.py flash`: the state is never `PENDING_VERIFY`, so the watchdog does nothing and no rollback occurs.

**Implication for connectivity testing**: The Raspberry Pi must be powered on and broadcasting the `AES-Gateway` access point BEFORE you power the ESP32. Give the Pi ~60 seconds to bring up `ap0` and Mosquitto before the ESP32 boots.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Monitor shows ROM bootloader output only | DTR/RTS toggled on port open | Add `--no-reset` to monitor command |
| Monitor shows `rst:0x1 (POWERON_RESET)` loop | CH340G keeps triggering reset | Use `--no-reset`; close all other serial apps |
| Firmware boots but `MQTT Connected` never appears | Raspberry Pi AP not up | Boot Pi first, wait 60s, then power ESP32 |
| Firmware rolls back after 30s | OTA state is PENDING_VERIFY + no MQTT | Start Pi first; or reflash with `idf.py flash` to reset OTA state |
| `A fatal error occurred: Failed to connect` | Wrong COM port or poor USB cable | Check Device Manager; try a different USB cable (data, not charge-only) |
| `idf.py: command not found` | ESP-IDF not activated | Open **ESP-IDF 5.2 CMD** shortcut, not regular PowerShell |

---

## Erase Flash (Full Reset)

Wipes all partitions including NVS and OTA state:

```cmd
esptool.py -p COM3 erase_flash
```

After erase you must reflash:

```cmd
idf.py -p COM3 flash
```

---

## Network Configuration Reference

Identity and credentials now come from **Kconfig** (`main/Kconfig.projbuild`), not
source code. Set them before building:

```cmd
idf.py menuconfig     → "AES Firmware Configuration"
```

or put them in a gitignored `sdkconfig.secrets`:

```
CONFIG_AES_WIFI_PASSWORD="<the AP passphrase — ask Son>"
```

and build with `SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.secrets" idf.py build`.

| Item | Kconfig symbol | Default |
|---|---|---|
| WiFi SSID | `CONFIG_AES_WIFI_SSID` | `AES-Gateway` |
| WiFi Password | `CONFIG_AES_WIFI_PASSWORD` | *(empty — must be set per build)* |
| Device ID | `CONFIG_AES_DEVICE_ID` | `esp32-cam-02` |
| MQTT Broker | `CONFIG_AES_MQTT_BROKER_URI` | `mqtt://192.168.4.1:1883` |
| Telemetry topic | — | `aes/telemetry/<device id>` |
| Telemetry interval | — | 5 seconds |

> The AP passphrase also lives in `raspberry-pi/hostapd.conf` — since this repo
> is public on GitHub, **rotate that passphrase** before any non-lab deployment
> and keep the new one only in `sdkconfig.secrets` + the Pi's local config.
