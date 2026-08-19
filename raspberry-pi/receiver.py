#!/usr/bin/env python3
"""
AES Telemetry Receiver — runs on Raspberry Pi.
Subscribes to aes/telemetry/+ and writes each message to data/telemetry/.

Environment overrides (useful for local testing on Windows):
  MQTT_HOST  — broker hostname/IP  (default: 192.168.4.1)
  MQTT_PORT  — TLS broker port      (default: 8883)
"""

import json
import math
import os
import re
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.mqtt_compat import configure_mqtt_client, make_mqtt_client
from agents.monitor_agent import Telemetry

BROKER_HOST = os.environ.get("MQTT_HOST", "192.168.4.1")
BROKER_PORT = int(os.environ.get("MQTT_PORT", "8883"))
TOPIC = "aes/telemetry/+"
MAX_PAYLOAD_BYTES = 4096
MAX_FILES_PER_DEVICE = max(1, int(os.environ.get("AES_TELEMETRY_MAX_FILES", "10000")))
MIN_WRITE_INTERVAL = float(os.environ.get("AES_TELEMETRY_MIN_INTERVAL", "0.1"))
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_last_write = {}

# Resolve data dir relative to repo root (one level up from raspberry-pi/)
DATA_DIR = (SCRIPT_DIR / ".." / "data" / "telemetry").resolve()


def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[receiver] Connected to MQTT broker at {BROKER_HOST}:{BROKER_PORT}", flush=True)
        client.subscribe(TOPIC)
        print(f"[receiver] Subscribed to {TOPIC}", flush=True)
    else:
        print(f"[receiver] Connection failed, rc={rc}", flush=True)


def on_message(client, userdata, msg):
    if len(msg.payload) > MAX_PAYLOAD_BYTES:
        print(f"[receiver] Payload too large on {msg.topic}", flush=True)
        return
    try:
        payload = json.loads(
            msg.payload.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite {value}")),
        )
        if not isinstance(payload, dict):
            raise TypeError("payload root must be an object")
        parts = msg.topic.split("/")
        if len(parts) != 3 or parts[:2] != ["aes", "telemetry"]:
            raise ValueError("unexpected topic")
        topic_device = parts[2]
        device_id = payload.get("device_id")
        if not isinstance(device_id, str) or not DEVICE_ID_RE.fullmatch(device_id):
            raise ValueError("invalid device_id")
        if device_id != topic_device:
            raise ValueError("topic and payload device_id differ")
        for key in ("cpu_percent", "memory_percent", "packet_rate"):
            value = payload.get(key)
            if isinstance(value, bool) or type(value) not in (int, float) or not math.isfinite(float(value)):
                raise ValueError(f"{key} must be a finite JSON number")
        connections = payload.get("connection_count")
        if isinstance(connections, bool) or type(connections) is not int:
            raise ValueError("connection_count must be a JSON integer")
        telemetry = Telemetry(
            device_id=device_id,
            timestamp=payload.get("timestamp"),
            cpu_percent=float(payload["cpu_percent"]),
            memory_percent=float(payload["memory_percent"]),
            packet_rate=float(payload["packet_rate"]),
            connection_count=connections,
        )
        validation_errors = telemetry.validate()
        if validation_errors:
            raise ValueError("; ".join(validation_errors))
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as e:
        print(f"[receiver] Bad payload on {msg.topic}: {e}", flush=True)
        return

    now = time.time()
    if now - _last_write.get(device_id, 0.0) < MIN_WRITE_INTERVAL:
        print(f"[receiver] Rate-limited {device_id}", flush=True)
        return
    _last_write[device_id] = now

    data_root = Path(DATA_DIR).resolve()
    device_dir = (data_root / device_id).resolve()
    if not device_dir.is_relative_to(data_root):
        print(f"[receiver] Rejected unsafe device path: {device_id}", flush=True)
        return
    ensure_dir(device_dir)

    # ISO 8601 timestamp safe for filenames (colons -> dashes, microseconds prevent collisions)
    ts = time.strftime("%Y-%m-%dT%H-%M-%S", time.gmtime(now))
    us = int((now % 1) * 1_000_000)
    filename = device_dir / f"{ts}-{us:06d}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f)

    # Always overwrite latest.json for quick reads
    latest = device_dir / "latest.json"
    latest_tmp = device_dir / "latest.json.tmp"
    with open(latest_tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(latest_tmp, latest)

    samples = sorted(path for path in device_dir.glob("*.json") if path.name != "latest.json")
    for old in samples[:-MAX_FILES_PER_DEVICE]:
        old.unlink()

    pkt = payload.get("packet_rate")
    mem = float(payload["memory_percent"])
    print(
        f"[receiver] {device_id} cpu={payload.get('cpu_percent')}% "
        f"mem={mem:.1f}% "
        f"pkt={pkt} "
        f"conn={payload.get('connection_count')}",
        flush=True,
    )


def main():
    ensure_dir(DATA_DIR)

    client = make_mqtt_client("aes-receiver")
    configure_mqtt_client(client, role="receiver")
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
