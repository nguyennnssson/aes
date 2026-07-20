#!/usr/bin/env python3
"""
AES Telemetry Receiver — runs on Raspberry Pi.
Subscribes to aes/telemetry/+ and writes each message to data/telemetry/.

Environment overrides (useful for local testing on Windows):
  MQTT_HOST  — broker hostname/IP  (default: 192.168.4.1)
  MQTT_PORT  — broker port          (default: 1883)
"""

import json
import os
import sys
import time
import paho.mqtt.client as mqtt

BROKER_HOST = os.environ.get("MQTT_HOST", "192.168.4.1")
BROKER_PORT = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC = "aes/telemetry/+"

# Resolve data dir relative to repo root (one level up from raspberry-pi/)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "..", "data", "telemetry")


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[receiver] Connected to MQTT broker at {BROKER_HOST}:{BROKER_PORT}", flush=True)
        client.subscribe(TOPIC)
        print(f"[receiver] Subscribed to {TOPIC}", flush=True)
    else:
        print(f"[receiver] Connection failed, rc={rc}", flush=True)


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[receiver] Bad payload on {msg.topic}: {e}", flush=True)
        return

    device_id = payload.get("device_id") or msg.topic.split("/")[-1]
    device_dir = os.path.join(DATA_DIR, device_id)
    ensure_dir(device_dir)

    # ISO 8601 timestamp safe for filenames (colons -> dashes, microseconds prevent collisions)
    now = time.time()
    ts = time.strftime("%Y-%m-%dT%H-%M-%S", time.gmtime(now))
    us = int((now % 1) * 1_000_000)
    filename = os.path.join(device_dir, f"{ts}-{us:06d}.json")

    with open(filename, "w") as f:
        json.dump(payload, f)

    # Always overwrite latest.json for quick reads
    latest = os.path.join(device_dir, "latest.json")
    with open(latest, "w") as f:
        json.dump(payload, f)

    pkt = payload.get("packet_rate")
    mem = payload.get("memory_percent", 0)
    print(
        f"[receiver] {device_id} cpu={payload.get('cpu_percent')}% "
        f"mem={mem:.1f}% "
        f"pkt={pkt} "
        f"conn={payload.get('connection_count')}",
        flush=True,
    )


def main():
    ensure_dir(DATA_DIR)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"[receiver] Connecting to {BROKER_HOST}:{BROKER_PORT} ...", flush=True)
    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except Exception as e:
        print(f"[receiver] Cannot connect: {e}", flush=True)
        sys.exit(1)

    client.loop_forever()


if __name__ == "__main__":
    main()
