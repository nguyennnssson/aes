#!/usr/bin/env python3
"""
End-to-end pipeline test for AES ESP32-cam data flow.

Tests:
  T1 - MQTT broker connectivity (localhost:1883)
  T2 - Receiver logic: on_message writes correct files to data/telemetry/
  T3 - Full MQTT round-trip: publish -> receiver -> data/ (needs broker)
  T4 - Wire contract: sample.json matches firmware JSON schema
  T5 - generate_sample_data.py produces correct output
  T6 - flash.ps1 syntax check (PowerShell -NonInteractive parse)

Run from repo root:
    python scripts/test_pipeline.py
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import types

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(REPO_ROOT, "data", "telemetry")
DEVICE_ID = "esp32-cam-02"
DEVICE_DIR = os.path.join(DATA_DIR, DEVICE_ID)
BROKER_HOST = "localhost"
BROKER_PORT = 1883

PASS = "[PASS]"
FAIL = "[FAIL]"
SKIP = "[SKIP]"

results = []


def record(label, passed, detail=""):
    tag = PASS if passed else FAIL
    msg = f"  {tag} {label}"
    if detail:
        msg += f"\n         {detail}"
    results.append((passed, msg))
    print(msg)


# ---------------------------------------------------------------------------
# T1 — MQTT Broker connectivity
# ---------------------------------------------------------------------------
def test_broker_connect():
    print("\nT1  MQTT broker connectivity (localhost:1883)")
    try:
        import paho.mqtt.client as mqtt

        connected = threading.Event()
        rc_box = [None]

        def on_connect(client, userdata, flags, rc):
            rc_box[0] = rc
            connected.set()

        from agents.mqtt_compat import make_mqtt_client
        c = make_mqtt_client("aes-test-probe")   # works on paho 1.x AND 2.x
        c.on_connect = on_connect
        c.connect(BROKER_HOST, BROKER_PORT, keepalive=5)
        c.loop_start()
        ok = connected.wait(timeout=5)
        c.loop_stop()
        c.disconnect()
        if ok and rc_box[0] == 0:
            record("broker accepts anonymous connections on localhost:1883", True)
            return True
        else:
            record(
                "broker connection",
                False,
                f"rc={rc_box[0]} — broker may require auth. "
                "Check C:\\Program Files\\mosquitto\\mosquitto.conf "
                "and ensure 'allow_anonymous true' + 'listener 1883'",
            )
            return False
    except Exception as e:
        record("broker connection", False, str(e))
        return False


# ---------------------------------------------------------------------------
# T2 — Receiver on_message logic (no broker needed)
# ---------------------------------------------------------------------------
def test_receiver_logic():
    print("\nT2  Receiver on_message logic (direct call, no broker)")
    import importlib.util, pathlib

    receiver_path = os.path.join(REPO_ROOT, "raspberry-pi", "receiver.py")
    spec = importlib.util.spec_from_file_location("receiver", receiver_path)
    mod = importlib.util.module_from_spec(spec)

    # Patch os.environ so DATA_DIR resolves to repo data/
    orig_env = os.environ.copy()
    os.environ["MQTT_HOST"] = "localhost"
    spec.loader.exec_module(mod)
    os.environ.clear()
    os.environ.update(orig_env)

    # Build a fake MQTT message
    fake_msg = types.SimpleNamespace()
    fake_msg.topic = f"aes/telemetry/{DEVICE_ID}"
    payload = {
        "device_id": DEVICE_ID,
        "cpu_percent": 15.0,
        "memory_percent": 38.5,
        "packet_rate": 0.0,
        "connection_count": 1,
    }
    fake_msg.payload = json.dumps(payload).encode()

    # Temporarily redirect DATA_DIR in the module
    orig_data_dir = mod.DATA_DIR
    mod.DATA_DIR = DATA_DIR
    mod.on_message(None, None, fake_msg)
    mod.DATA_DIR = orig_data_dir

    # Verify files
    latest = os.path.join(DEVICE_DIR, "latest.json")
    if not os.path.exists(latest):
        record("on_message writes latest.json", False, f"File not found: {latest}")
        return False
    with open(latest) as f:
        written = json.load(f)
    record("on_message writes latest.json", True, f"-> {latest}")

    match = written == payload
    record(
        "latest.json content matches published payload",
        match,
        json.dumps(written) if not match else "",
    )

    # Verify a timestamped file also exists
    ts_files = [
        x
        for x in os.listdir(DEVICE_DIR)
        if x.endswith(".json") and x not in ("latest.json", "sample.json")
    ]
    record(
        "on_message writes timestamped .json file",
        len(ts_files) > 0,
        f"found: {ts_files[-1]}" if ts_files else "no timestamped files found",
    )
    return match


# ---------------------------------------------------------------------------
# T3 — Full MQTT round-trip (publish -> receiver -> data/)
# ---------------------------------------------------------------------------
def test_mqtt_roundtrip(broker_ok):
    print("\nT3  Full MQTT round-trip (publish -> receiver -> file)")
    if not broker_ok:
        results.append((None, f"  {SKIP} MQTT round-trip (broker not reachable)"))
        print(f"  {SKIP} MQTT round-trip (broker not reachable)")
        return

    import paho.mqtt.client as mqtt

    received_files_before = set(
        f for f in os.listdir(DEVICE_DIR) if f.endswith(".json") and f not in ("sample.json",)
    )

    # Launch receiver as subprocess
    env = os.environ.copy()
    env["MQTT_HOST"] = "localhost"
    env["MQTT_PORT"] = "1883"
    receiver_path = os.path.join(REPO_ROOT, "raspberry-pi", "receiver.py")
    proc = subprocess.Popen(
        [sys.executable, receiver_path],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    time.sleep(2)  # give receiver time to connect and subscribe

    # Publish 3 messages
    published = threading.Event()
    pub_count = [0]
    topic = f"aes/telemetry/{DEVICE_ID}"

    def on_pub(client, userdata, mid):
        pub_count[0] += 1
        if pub_count[0] >= 3:
            published.set()

    from agents.mqtt_compat import make_mqtt_client
    pub = make_mqtt_client("aes-test-pub")   # works on paho 1.x AND 2.x
    pub.on_publish = on_pub
    pub.connect(BROKER_HOST, BROKER_PORT)
    pub.loop_start()

    for i in range(3):
        payload = json.dumps(
            {
                "device_id": DEVICE_ID,
                "cpu_percent": round(15.0 + i * 0.5, 1),
                "memory_percent": round(38.5 + i * 0.3, 2),
                "packet_rate": 0.0,
                "connection_count": 1,
            }
        )
        pub.publish(topic, payload, qos=1)
        time.sleep(0.3)

    published.wait(timeout=5)
    pub.loop_stop()
    pub.disconnect()

    time.sleep(2)  # let receiver flush writes
    proc.terminate()
    stdout, _ = proc.communicate(timeout=5)

    # Count new files
    received_files_after = set(
        f for f in os.listdir(DEVICE_DIR) if f.endswith(".json") and f not in ("sample.json",)
    )
    new_files = received_files_after - received_files_before
    # Receiver uses microsecond-precision filenames so 3 rapid publishes = 3 distinct files
    record(
        f"receiver stored {len(new_files)} new file(s) from 3 MQTT messages",
        len(new_files) >= 3,
        f"new files: {sorted(new_files)}" if new_files else "no new files written — check broker auth / receiver startup time",
    )

    # Show receiver stdout snippet
    lines = [l for l in stdout.splitlines() if "[receiver]" in l]
    if lines:
        print(f"         receiver output: {lines[-1]}")


# ---------------------------------------------------------------------------
# T4 — Wire contract: sample.json schema
# ---------------------------------------------------------------------------
def test_wire_contract():
    print("\nT4  Wire contract: sample.json matches firmware JSON schema")
    sample_path = os.path.join(DEVICE_DIR, "sample.json")
    if not os.path.exists(sample_path):
        record("sample.json exists", False, f"Not found: {sample_path}")
        return

    with open(sample_path) as f:
        sample = json.load(f)

    required_keys = {
        "device_id": str,
        "cpu_percent": (int, float),
        "memory_percent": (int, float),
        "packet_rate": (int, float),
        "connection_count": int,
    }
    errors = []
    for key, typ in required_keys.items():
        if key not in sample:
            errors.append(f"missing key: {key}")
        elif not isinstance(sample[key], typ):
            errors.append(f"{key}: expected {typ}, got {type(sample[key])}")

    record("sample.json has all required firmware fields", not errors, "; ".join(errors))
    record(
        "sample.json device_id matches expected",
        sample.get("device_id") == DEVICE_ID,
        f"got: {sample.get('device_id')}",
    )
    print(f"         sample: {json.dumps(sample)}")


# ---------------------------------------------------------------------------
# T5 — generate_sample_data.py re-run
# ---------------------------------------------------------------------------
def test_generate_sample_data():
    print("\nT5  scripts/generate_sample_data.py re-run")
    script = os.path.join(REPO_ROOT, "scripts", "generate_sample_data.py")
    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    passed = result.returncode == 0
    record(
        "generate_sample_data.py exits 0",
        passed,
        result.stderr.strip()[-200:] if not passed else "",
    )
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    if lines:
        print(f"         last line: {lines[-1]}")
    sample_path = os.path.join(DEVICE_DIR, "sample.json")
    record("sample.json refreshed after re-run", os.path.exists(sample_path))


# ---------------------------------------------------------------------------
# T6 — flash.ps1 PowerShell syntax check
# ---------------------------------------------------------------------------
def test_flash_ps1():
    print("\nT6  esp32-cam/flash.ps1 PowerShell syntax check")
    ps1_path = os.path.join(REPO_ROOT, "esp32-cam", "flash.ps1")
    if not os.path.exists(ps1_path):
        record("flash.ps1 exists", False, ps1_path)
        return

    powershell = shutil.which("pwsh") or shutil.which("powershell") or shutil.which("powershell.exe")
    if powershell is None:
        results.append((None, f"  {SKIP} flash.ps1 PowerShell syntax check (no PowerShell interpreter found)"))
        print(f"  {SKIP} flash.ps1 PowerShell syntax check (no PowerShell interpreter found)")
    else:
        result = subprocess.run(
            [
                powershell,
                "-NonInteractive",
                "-Command",
                f"$null = [System.Management.Automation.Language.Parser]::ParseFile('{ps1_path}', [ref]$null, [ref]$null); Write-Host 'syntax OK'",
            ],
            capture_output=True,
            text=True,
        )
        passed = "syntax OK" in result.stdout
        record(
            "flash.ps1 PowerShell syntax is valid",
            passed,
            result.stderr.strip()[-200:] if not passed else "",
        )
    record("flash.ps1 contains --no-reset flag", True if "--no-reset" in open(ps1_path).read() else False)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print(" AES ESP32-CAM Pipeline Test Suite")
    print("=" * 60)

    broker_ok = test_broker_connect()
    test_receiver_logic()
    test_mqtt_roundtrip(broker_ok)
    test_wire_contract()
    test_generate_sample_data()
    test_flash_ps1()

    print("\n" + "=" * 60)
    passed = [r for ok, r in results if ok is True]
    failed = [r for ok, r in results if ok is False]
    skipped = [r for ok, r in results if ok is None]
    print(f" RESULTS: {len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped")
    if failed:
        print("\n FAILURES:")
        for r in failed:
            print(r)
    print("=" * 60)

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
