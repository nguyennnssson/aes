#!/usr/bin/env python3
"""
Simulate 10 readings from esp32-cam-02 using the same receiver.py write logic.

Run this from the repo root on any machine (no MQTT broker needed):
    python scripts/generate_sample_data.py

Writes to:
    data/telemetry/esp32-cam-02/<timestamp>.json   (one per reading)
    data/telemetry/esp32-cam-02/latest.json         (last reading)
    data/telemetry/esp32-cam-02/sample.json         (committed reference)

The sample.json is tracked by git (exception in .gitignore) so reviewers
and CI can verify the telemetry wire contract without running real hardware.
"""

import json
import math
import os
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.join(SCRIPT_DIR, "..")
DATA_DIR = os.path.join(REPO_ROOT, "data", "telemetry")

DEVICE_ID = "esp32-cam-02"

# Realistic baseline values matching ewma_baseline.json
BASE_CPU     = 15.0   # placeholder from firmware (TODO: wire real counter)
BASE_MEM     = 38.5   # live heap from esp_get_free_heap_size()
BASE_PKT     = 0.0    # placeholder from firmware (TODO: wire real RX/TX counter)
BASE_CONN    = 1      # 1 = MQTT connected

READINGS = 10
INTERVAL_SEC = 5


def make_payload(i: int) -> dict:
    # Simulate slight heap variation as tasks allocate/free buffers
    mem_variation = math.sin(i * 0.7) * 2.0
    return {
        "device_id": DEVICE_ID,
        "cpu_percent": round(BASE_CPU + (i % 3) * 0.5, 2),
        "memory_percent": round(BASE_MEM + mem_variation, 2),
        "packet_rate": BASE_PKT,
        "connection_count": BASE_CONN,
    }


def write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def main():
    device_dir = os.path.join(DATA_DIR, DEVICE_ID)
    os.makedirs(device_dir, exist_ok=True)

    print(f"[generate_sample_data] Writing {READINGS} readings to {device_dir}")

    for i in range(READINGS):
        payload = make_payload(i)

        ts = time.strftime("%Y-%m-%dT%H-%M-%S", time.gmtime())
        ts_path = os.path.join(device_dir, f"{ts}.json")
        write_json(ts_path, payload)
        write_json(os.path.join(device_dir, "latest.json"), payload)

        mem = payload["memory_percent"]
        print(
            f"  [{i+1:02d}/{READINGS}] cpu={payload['cpu_percent']}% "
            f"mem={mem:.1f}% "
            f"pkt={payload['packet_rate']} "
            f"conn={payload['connection_count']}  -> {os.path.basename(ts_path)}"
        )

        if i < READINGS - 1:
            time.sleep(1)  # 1s between samples (faster than real 5s for quick run)

    # Write the committed sample (last reading — representative stable state)
    sample = make_payload(READINGS - 1)
    sample_path = os.path.join(device_dir, "sample.json")
    write_json(sample_path, sample)
    print(f"\n[generate_sample_data] Committed sample written: {sample_path}")
    print(f"[generate_sample_data] Done — {READINGS} readings stored in {device_dir}")


if __name__ == "__main__":
    main()
