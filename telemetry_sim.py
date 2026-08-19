"""
AES — Telemetry Simulator (Hardware Stub)
Mimics ESP32-CAM and IP camera telemetry over MQTT.

Normal mode: replays real readings from data/telemetry/{device_id}/consolidated.json
             when available, cycling through them. Falls back to hardcoded ranges for
             devices that have no real data file yet.
Attack/stealth mode: always uses hardcoded ranges (same as before).

Usage:
  python telemetry_sim.py                          # all devices, normal mode
  python telemetry_sim.py --attack esp32-cam-01    # loud attack (defaults catch it)
  python telemetry_sim.py --attack all             # loud attack on every device
  python telemetry_sim.py --stealth esp32-cam-01   # low-and-slow: ~45% spikes that the
                                                   # default 0.5 threshold MISSES (for the
                                                   # self-improvement before/after demo)

MQTT topic: aes/telemetry/{device_id}
Publish rate: every 5 seconds per device
"""

import argparse
import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from agents.mqtt_compat import configure_mqtt_client, make_mqtt_client

# ─── CONFIG ──────────────────────────────────────────────────────────────────

BROKER_HOST       = os.getenv("MQTT_HOST", "localhost")
BROKER_PORT       = int(os.getenv("MQTT_PORT", "8883"))
PUBLISH_INTERVAL  = 5   # seconds between readings
TELEMETRY_DIR     = Path("data/telemetry")
SIM_STATE_PATH    = Path("config/sim_state.json")

# ─── DEVICE PROFILES (attack + stealth + normal fallback) ────────────────────
# Normal ranges are only used when no consolidated.json exists for the device.
# Attack and stealth ranges are always hardcoded — they represent what the
# telemetry looks like when a real attack has compromised the device.

DEVICE_PROFILES = {
    "esp32-cam-01": {
        "model": "ESP32-CAM",
        "normal": {
            "cpu_percent":      (18.0, 24.0),
            "memory_percent":   (36.0, 42.0),
            "packet_rate":      (40.0, 55.0),
            "connection_count": (2, 3),
        },
        # Mirai-style botnet: device recruited for DDoS
        "attack": {
            "cpu_percent":      (82.0, 94.0),
            "memory_percent":   (40.0, 48.0),
            "packet_rate":      (460.0, 540.0),
            "connection_count": (44, 58),
        },
        # Throttled variant: ~45% above baseline — under the 0.5 default threshold
        "stealth": {
            "cpu_percent":      (30.0, 31.0),
            "memory_percent":   (55.5, 57.0),
            "packet_rate":      (68.0, 70.0),
            "connection_count": (3, 3),
        },
    },
    "esp32-cam-02": {
        "model": "ESP32-CAM",
        "normal": {
            "cpu_percent":      (17.0, 23.0),
            "memory_percent":   (35.0, 41.0),
            "packet_rate":      (38.0, 52.0),
            "connection_count": (2, 3),
        },
        "attack": {
            "cpu_percent":      (80.0, 92.0),
            "memory_percent":   (39.0, 47.0),
            "packet_rate":      (440.0, 520.0),
            "connection_count": (40, 55),
        },
        "stealth": {
            "cpu_percent":      (28.5, 29.5),
            "memory_percent":   (54.0, 55.5),
            "packet_rate":      (64.5, 66.5),
            "connection_count": (3, 3),
        },
    },
    "esp32-cam-03": {
        "model": "ESP32-CAM",
        "normal": {
            "cpu_percent":      (19.0, 25.0),
            "memory_percent":   (37.0, 43.0),
            "packet_rate":      (42.0, 57.0),
            "connection_count": (2, 4),
        },
        "attack": {
            "cpu_percent":      (83.0, 95.0),
            "memory_percent":   (42.0, 50.0),
            "packet_rate":      (470.0, 560.0),
            "connection_count": (46, 60),
        },
        "stealth": {
            "cpu_percent":      (31.5, 32.5),
            "memory_percent":   (57.0, 58.5),
            "packet_rate":      (71.0, 73.0),
            "connection_count": (3, 4),
        },
    },
    "tapo-c200-01": {
        "model": "TP-Link Tapo C200",
        "normal": {
            "cpu_percent":      (12.0, 20.0),
            "memory_percent":   (45.0, 55.0),
            "packet_rate":      (20.0, 35.0),
            "connection_count": (1, 3),
        },
        # Credential stuffing / unauthorized access attempt
        "attack": {
            "cpu_percent":      (65.0, 80.0),
            "memory_percent":   (60.0, 75.0),
            "packet_rate":      (180.0, 250.0),
            "connection_count": (20, 35),
        },
        "stealth": {
            "cpu_percent":      (23.0, 23.7),
            "memory_percent":   (72.0, 74.0),
            "packet_rate":      (39.5, 40.7),
            "connection_count": (2, 3),
        },
    },
}


# ─── SIM STATE (written by the pipeline when a device is patched) ────────────

def load_sim_state() -> dict:
    """Returns {device_id: "patched", ...} — read on every tick so changes apply immediately."""
    try:
        return json.loads(SIM_STATE_PATH.read_text()) if SIM_STATE_PATH.exists() else {}
    except Exception:
        return {}


# ─── REAL DATA LOADER ────────────────────────────────────────────────────────

def load_real_readings(device_id: str) -> list:
    """
    Load real telemetry readings from data/telemetry/{device_id}/consolidated.json.
    Returns the list of reading dicts, or [] if the file doesn't exist.
    """
    path = TELEMETRY_DIR / device_id / "consolidated.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        readings = data.get("readings", [])
        if readings:
            print(f"[SIM] {device_id}: loaded {len(readings)} real readings from {path}")
        return readings
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[SIM] {device_id}: failed to load {path} ({e}) — using hardcoded ranges")
        return []


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def sample(range_tuple: tuple) -> float:
    """Random value within a range. Integers stay integers."""
    lo, hi = range_tuple
    if isinstance(lo, int):
        return float(random.randint(lo, hi))
    return round(random.uniform(lo, hi), 1)


def build_payload(device_id: str, mode: str,
                  real_readings: dict, replay_index: dict) -> tuple:
    """
    Build a telemetry payload dict and a source label for logging.

    Normal mode: replays from real_readings[device_id] if available (cycling),
                 falls back to hardcoded ranges otherwise.
    Attack/stealth: always hardcoded ranges.

    Returns (payload_dict, source_label).
    """
    if mode == "normal" and real_readings.get(device_id):
        readings = real_readings[device_id]
        idx = replay_index.get(device_id, 0)
        r = readings[idx % len(readings)]
        replay_index[device_id] = idx + 1
        payload = {
            "device_id":        device_id,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "cpu_percent":      round(float(r["cpu_percent"]), 2),
            "memory_percent":   round(float(r["memory_percent"]), 2),
            "packet_rate":      round(float(r["packet_rate"]), 2),
            "connection_count": int(r["connection_count"]),
        }
        return payload, f"real[{idx % len(readings) + 1}/{len(readings)}]"

    profile = DEVICE_PROFILES[device_id][mode]
    payload = {
        "device_id":        device_id,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "cpu_percent":      sample(profile["cpu_percent"]),
        "memory_percent":   sample(profile["memory_percent"]),
        "packet_rate":      sample(profile["packet_rate"]),
        "connection_count": int(sample(profile["connection_count"])),
    }
    return payload, "sim"


# ─── MQTT CALLBACKS ──────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[SIM] Connected to Mosquitto at {BROKER_HOST}:{BROKER_PORT}")
    else:
        print(f"[SIM] Connection failed — rc={rc}. Is Mosquitto running?")


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AES Telemetry Simulator")
    parser.add_argument(
        "--attack",
        metavar="DEVICE_ID",
        default=None,
        help="Device ID to put in LOUD attack mode, or 'all' for every device",
    )
    parser.add_argument(
        "--stealth",
        metavar="DEVICE_ID",
        default=None,
        help="Device ID to put in STEALTH (low-and-slow) mode, or 'all'",
    )
    args = parser.parse_args()

    def resolve(arg, label):
        if not arg:
            return set()
        if arg == "all":
            return set(DEVICE_PROFILES.keys())
        if arg in DEVICE_PROFILES:
            return {arg}
        print(f"[SIM] Unknown device for {label}: {arg}")
        print(f"[SIM] Valid IDs: {list(DEVICE_PROFILES.keys())}")
        return None

    attacking  = resolve(args.attack,  "--attack")
    stealthing = resolve(args.stealth, "--stealth")
    if attacking is None or stealthing is None:
        return

    # Load real readings for every device (silently skips missing files)
    real_readings = {
        device_id: load_real_readings(device_id)
        for device_id in DEVICE_PROFILES
    }
    replay_index = {}   # tracks position in each device's real reading list

    # Connect to Mosquitto
    client = make_mqtt_client("aes-telemetry-sim")
    configure_mqtt_client(client, role="simulator")
    client.on_connect = on_connect
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    client.loop_start()

    time.sleep(1)

    print(f"\n[SIM] Publishing telemetry every {PUBLISH_INTERVAL}s")
    print(f"[SIM] Devices: {list(DEVICE_PROFILES.keys())}")
    if attacking:
        print(f"[SIM] LOUD ATTACK mode on: {list(attacking)}")
    if stealthing:
        print(f"[SIM] STEALTH mode on: {list(stealthing)}")
    if not attacking and not stealthing:
        print(f"[SIM] All devices in NORMAL mode")
    print(f"[SIM] Press Ctrl+C to stop\n")

    tick = 0
    try:
        while True:
            tick += 1
            sim_state = load_sim_state()
            for device_id in DEVICE_PROFILES:
                if sim_state.get(device_id) == "patched":
                    mode, flag = "normal", "🩹 patched"
                elif device_id in attacking:
                    mode, flag = "attack", "🔴 ATTACK "
                elif device_id in stealthing:
                    mode, flag = "stealth", "🟡 STEALTH"
                else:
                    mode, flag = "normal", "🟢 normal "

                payload, source = build_payload(
                    device_id, mode, real_readings, replay_index
                )
                topic = f"aes/telemetry/{device_id}"
                client.publish(topic, json.dumps(payload), qos=0)

                print(
                    f"[tick {tick:03d}] {device_id:20s} | {flag} | "
                    f"cpu={payload['cpu_percent']:5.2f}% "
                    f"pkt={payload['packet_rate']:6.2f}/s "
                    f"conn={payload['connection_count']:2d} "
                    f"({source})"
                )

            print()
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print("\n[SIM] Stopped.")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
