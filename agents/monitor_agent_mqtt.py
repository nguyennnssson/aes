"""
AES — Monitor Agent MQTT Wrapper
=================================
Owner: Son Nguyen (AI Infra)
Moved to: agents/monitor_agent_mqtt.py

WHAT IT DOES:
  Subscribes to MQTT telemetry from all devices, runs EWMA anomaly detection,
  and fires the full incident pipeline when an attack is confirmed.

HOW TO RUN (always from repo root with venv active):
  source venv/bin/activate
  python -m agents.monitor_agent_mqtt

KEEP THIS RUNNING. It loops forever and handles reconnects automatically.
Start it before the telemetry simulator or real hardware.

PIPELINE ON ANOMALY:
  1. write_incident_log()      — saves to aes_incidents.jsonl
  2. query_intel()             — local vector index: relevance-filtered CVE chunks
  3. hermes.analyze_incident() — Hermes reasoning layer
  4. respond()                 — routes verdict to Solution 1/2/3, posts Discord alert
  5. hitl.propose_skill()      — Solution 3 learning loop (auto, cooldown-gated)

MQTT TOPICS:
  Subscribe: aes/telemetry/+   (all devices)
  Broker:    MQTT_HOST:8883 with certificate validation and per-role credentials
"""

import json
import math
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# Load .env from repo root before any API clients are initialized
load_dotenv(Path(__file__).parent.parent / ".env")

from agents.mqtt_compat import configure_mqtt_client, make_mqtt_client
from agents.monitor_agent import (
    MonitorAgent,
    Telemetry,
    DEVICE_REGISTRY,
    initialize_incident_audit,
    write_incident_log,
    write_normal_sample,
)

# ─── CONFIG ──────────────────────────────────────────────────────────────────

BROKER_HOST = os.getenv("MQTT_HOST", "localhost")
BROKER_PORT  = int(os.getenv("MQTT_PORT", "8883"))
TOPIC        = "aes/telemetry/+"        # canonical schema: aes/telemetry/{device_id}
MAX_PAYLOAD_BYTES = 4096

# Suppress repeat incidents on the same device for this long. Without this, a
# sustained attack fires a full Intel+Hermes+Discord pipeline on every reading.
COOLDOWN_SECONDS = 90

# Console: suppress routine "Normal" lines; print a liveness heartbeat every N readings.
HEARTBEAT_EVERY = 24

# Fleet status snapshot for the dashboard (config/fleet_status.json, gitignored).
FLEET_PATH = Path(__file__).parent.parent / "config" / "fleet_status.json"

# ─── INTEL AGENT ─────────────────────────────────────────────────────────────

from agents.intel_agent import IntelAgent
from agents.response_agent import respond, update_incident_fields

_intel_agent = IntelAgent()

def run_intel(device_id: str, reason: str) -> str:
    device_info = DEVICE_REGISTRY.get(device_id, {})
    model       = device_info.get("model", device_id)
    ctx = _intel_agent.query(
        device_model=model,
        firmware_version="unknown",
        attack_signature=reason,
    )
    return ctx.formatted

# ─── HERMES + LEARNING LOOP ──────────────────────────────────────────────────

from agents.hermes import Hermes
from agents.llm_client import make_hermes_client
from skills.hitl import HITLOrchestrator

_hermes = Hermes(client=make_hermes_client())
_hitl   = HITLOrchestrator(hermes=_hermes)

def call_hermes(incident_id: str, device_id: str, reason: str, intel: str) -> dict:
    device_info    = DEVICE_REGISTRY.get(device_id, {})
    solution_track = device_info.get("solution_track", 0)
    verdict = _hermes.analyze_incident(
        device_id=device_id,
        anomaly_reason=reason,
        intel_context=intel,
        solution_track=solution_track,
    )
    return verdict.to_dict()

# ─── DEVICE STATE ────────────────────────────────────────────────────────────
# One MonitorAgent per device. Created lazily on first message seen.
# This means new devices are handled automatically — no config change needed.

agents: dict[str, MonitorAgent] = {}

# Tracks devices with an in-flight incident — guards against reentrancy.
active_incidents: set[str] = set()
# Tracks the last incident time per device — enforces COOLDOWN_SECONDS.
last_incident_time: dict[str, float] = {}
# Rolling counter for the console heartbeat.
_reading_count = 0
# Latest status per device, mirrored to FLEET_PATH for the dashboard.
fleet_state: dict[str, dict] = {}
# Per-device counters for sampling NORMAL readings into aes_normals.jsonl —
# the sandbox's false-positive corpus. Every reading would bloat the file;
# 1-in-N keeps it representative and bounded.
_normal_counts: dict[str, int] = {}
NORMAL_SAMPLE_EVERY = 5

# Serializes fleet_status.json writes now that on_message (paho thread) and the
# incident worker can both touch fleet_state.
_fleet_lock = threading.Lock()

# Incident jobs are handed to a background worker so the MQTT callback thread
# never blocks on Intel/Hermes/gates/flash (REVIEW P0-2). paho delivers messages
# on ONE thread; running remediation inline blinds the whole fleet for minutes.
_incident_queue: "queue.Queue" = queue.Queue(maxsize=100)

def get_agent(device_id: str) -> MonitorAgent:
    if device_id not in agents:
        agents[device_id] = MonitorAgent(device_id)
        print(f"[MONITOR] New device registered: {device_id}")
    return agents[device_id]

# ─── MQTT CALLBACKS ──────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        client.subscribe(TOPIC, qos=0)
        print(f"[MONITOR] Connected to Mosquitto — subscribed to '{TOPIC}'")
        print(f"[MONITOR] Watching {len(DEVICE_REGISTRY)} registered devices")
        print(f"[MONITOR] Waiting for telemetry...\n")
    else:
        print(f"[MONITOR] Connection failed — rc={rc}")
        sys.exit(1)

def on_message(client, userdata, msg):
    global _reading_count

    # ── Parse topic → device_id ──────────────────────────────────────────────
    # Topic format: devices/{device_id}/telemetry
    parts = msg.topic.split("/")
    if len(parts) != 3 or parts[0] != "aes" or parts[1] != "telemetry":
        print(f"[MONITOR] Unexpected topic format: {msg.topic} — skipping")
        return
    device_id = parts[2]

    # ── Parse payload → Telemetry ────────────────────────────────────────────
    if len(msg.payload) > MAX_PAYLOAD_BYTES:
        print(f"[MONITOR] Payload too large on {msg.topic}: {len(msg.payload)} bytes")
        return

    def _reject_constant(value):
        raise ValueError(f"non-finite JSON number {value}")

    try:
        data = json.loads(msg.payload.decode("utf-8"), parse_constant=_reject_constant)
        if not isinstance(data, dict):
            raise TypeError("payload root must be an object")
        for key in ("cpu_percent", "memory_percent", "packet_rate"):
            if isinstance(data.get(key), bool) or type(data.get(key)) not in (int, float):
                raise TypeError(f"{key} must be a JSON number")
            if not math.isfinite(float(data[key])):
                raise ValueError(f"{key} must be finite")
        if isinstance(data.get("connection_count"), bool) or type(data.get("connection_count")) is not int:
            raise TypeError("connection_count must be a JSON integer")
        telemetry = Telemetry(
            device_id        = data["device_id"],
            timestamp        = data["timestamp"],
            cpu_percent      = float(data["cpu_percent"]),
            memory_percent   = float(data["memory_percent"]),
            packet_rate      = float(data["packet_rate"]),
            connection_count = int(data["connection_count"]),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, OverflowError) as e:
        print(f"[MONITOR] Bad payload on {msg.topic}: {e}")
        return

    # ── Anti-spoof: payload id must match the topic id (REVIEW P1-7) ──────────
    # The topic segment selects which device's baseline we update; the payload id
    # flows into incidents, registry lookups, and Sol 2 IP resolution. If they
    # disagree, a host could poison another device's baseline or trigger a
    # quarantine/patch against a victim device by publishing forged telemetry.
    if telemetry.device_id != device_id:
        print(f"[MONITOR] Rejected spoofed telemetry: topic={device_id} payload={telemetry.device_id}")
        return

    # Enrollment is strict by default. The broker ACL also binds a device's MQTT
    # username to its own topic. Labs can explicitly opt into discovery.
    if device_id not in DEVICE_REGISTRY and os.getenv("AES_ALLOW_UNREGISTERED_DEVICES") != "1":
        print(f"[MONITOR] Rejected unregistered device: {device_id}")
        return

    # ── Run anomaly detection ─────────────────────────────────────────────────
    agent  = get_agent(device_id)
    result = agent.check(telemetry)

    # ── Console output: quiet by default so incidents stand out ───────────────
    # Suppress the routine "Normal" flood; print only anomalies, elevated/invalid
    # readings, and a periodic heartbeat so you can see the monitor is alive.
    _reading_count += 1
    now = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
    quiet = (not result.is_anomaly) and result.reason.startswith(("Normal", "Warming"))

    if not quiet:
        status = "🚨 ANOMALY" if result.is_anomaly else "🟡 watch  "
        print(
            f"[{now}] {device_id:20s} | {status} | "
            f"cpu={telemetry.cpu_percent:5.1f}% "
            f"pkt={telemetry.packet_rate:6.1f}/s "
            f"conn={telemetry.connection_count:2d} | "
            f"{result.reason}"
        )
    elif _reading_count % HEARTBEAT_EVERY == 0:
        print(f"[{now}] 🟢 fleet quiet — {len(agents)} devices · {_reading_count} clean readings")

    # ── Mirror this device's status to the dashboard fleet file ───────────────
    if result.is_anomaly:
        fstat = "attack"
    elif result.reason.startswith("Elevated"):
        fstat = "elevated"
    elif result.reason.startswith("Warming"):
        fstat = "warming"
    else:
        fstat = "clean"
    with _fleet_lock:
        try:
            fleet_state[device_id] = {
                "status":           fstat,
                "cpu_percent":      telemetry.cpu_percent,
                "memory_percent":   telemetry.memory_percent,
                "packet_rate":      telemetry.packet_rate,
                "connection_count": telemetry.connection_count,
                "last_seen":        now,
            }
            _tmp = FLEET_PATH.with_suffix(".json.tmp")
            _tmp.write_text(json.dumps(fleet_state))
            os.replace(_tmp, FLEET_PATH)
        except Exception:
            pass

    if not result.is_anomaly:
        # Feed the sandbox's false-positive corpus with sampled post-warmup
        # non-incident readings. We sample BOTH "Normal" and "Elevated" readings
        # (REVIEW P1-6): the elevated-but-benign 25-45% jitter band is exactly
        # what a tightened 0.30-0.35 threshold risks false-positiving on, so
        # excluding it made the FP gate optimistic. Both are ground-truth
        # non-incidents; they keep status="NORMAL" so the sandbox filter is happy.
        if result.reason.startswith(("Normal", "Elevated")):
            _normal_counts[device_id] = _normal_counts.get(device_id, 0) + 1
            if _normal_counts[device_id] % NORMAL_SAMPLE_EVERY == 0:
                try:
                    write_normal_sample(result)
                except Exception:
                    pass
        return

    # ── Anomaly detected: gate, log, and hand off to the worker ──────────────
    # Everything above ran on paho's single network thread and must stay fast.
    # The heavy remediation (Intel + Hermes + gates + flash) runs in a background
    # worker so telemetry from other devices keeps flowing during an incident.
    now_ts = time.time()
    if device_id in active_incidents or (now_ts - last_incident_time.get(device_id, 0.0)) < COOLDOWN_SECONDS:
        print(f"  ⏸ [{device_id}] incident in-flight or within {COOLDOWN_SECONDS}s cooldown — skipping")
        return

    # Mark in-flight BEFORE enqueue so a burst of readings can't double-enqueue.
    active_incidents.add(device_id)
    last_incident_time[device_id] = now_ts

    print(f"\n{'='*60}")
    print(f"  ANOMALY CONFIRMED on {device_id}")
    print(f"  Confidence : {result.confidence:.0%}")
    print(f"  Deviations : {result.deviations}")
    print(f"  Baseline   : {result.baseline}")

    device_info = DEVICE_REGISTRY.get(device_id, {"model": "unknown", "solution_track": 0})
    incident_id = write_incident_log(result, device_info)
    print(f"  ✅ Incident logged: {incident_id} — queued for remediation")
    print(f"{'='*60}\n")

    try:
        _incident_queue.put_nowait({
            "incident_id": incident_id,
            "device_id":   device_id,
            "device_info": device_info,
            "reason":      result.reason,
            "confidence":  result.confidence,
            "detected_at": now_ts,
        })
    except queue.Full:
        active_incidents.discard(device_id)
        update_incident_fields(incident_id, stage="queue_full", status="FAILED")
        print(f"  [MONITOR] Remediation queue full — {incident_id} held as FAILED")


def _process_incident(job: dict) -> None:
    """Run the full remediation pipeline for one incident. Executes on the worker
    thread — NEVER on the MQTT callback thread. Always releases the device in
    finally so detection keeps working after any failure."""
    device_id   = job["device_id"]
    incident_id = job["incident_id"]
    device_info = job["device_info"]
    reason      = job["reason"]
    try:
        # Step 2: Intel Agent — query the embedded vector index for relevant CVEs
        print(f"  🔍 [{device_id}] Querying Intel Agent...")
        intel_report = run_intel(device_id, reason)
        print(f"  {intel_report[:200]}...")
        update_incident_fields(incident_id, stage="intel_done")

        # Step 3: Hermes — deep analysis
        verdict = call_hermes(incident_id, device_id, reason, intel_report)
        print(f"\n  📋 [{device_id}] Verdict: Solution {verdict['solution_track']} | {verdict['action']}")
        update_incident_fields(incident_id, verdict=verdict, stage="hermes_done")

        # Step 4: Response Agent — route verdict → execute → Discord alert
        incident_record = {
            "incident_id":    incident_id,
            "device_id":      device_id,
            "device_model":   device_info.get("model", "unknown"),
            "solution_track": device_info.get("solution_track", 0),
            "reason":         reason,
            "confidence":     job["confidence"],
            "detected_at":    job["detected_at"],   # true detect→respond latency
            "status":         "OPEN",
        }
        respond(incident_record, verdict)

        # Step 5: HITL learning loop — propose improved detection params
        print(f"\n  🔁 [{device_id}] Proposing Hermes skill update...")
        try:
            _hitl.propose_skill(
                incident_id   = incident_id,
                device_id     = device_id,
                anomaly_reason= reason,
                intel_context = intel_report,
                cve_id        = verdict.get("cve_id", "UNKNOWN"),
                device_type   = device_info.get("model", ""),
            )
        except Exception as e:
            print(f"  [HITL] propose_skill failed: {e}")
    except Exception as e:
        print(f"  ❌ Incident pipeline error on {device_id}: {e}")
    finally:
        active_incidents.discard(device_id)


def _incident_worker() -> None:
    """Daemon loop: drain the incident queue one job at a time. Serializing
    remediations is intentional — the cooldown/active_incidents gates already
    prevent flooding, and one flash/patch at a time is the safe behavior."""
    while True:
        job = _incident_queue.get()
        try:
            _process_incident(job)
        finally:
            _incident_queue.task_done()


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"[MONITOR] Unexpected disconnect — rc={rc}. Reconnecting...")

# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    audit_problems = initialize_incident_audit(production=os.getenv("AES_PRODUCTION") == "1")
    if audit_problems:
        raise RuntimeError("incident audit verification failed: " + "; ".join(audit_problems[:5]))
    print("=" * 60)
    print("AES — Monitor Agent (MQTT Mode)")
    print(f"Broker : {BROKER_HOST}:{BROKER_PORT}")
    print(f"Topic  : {TOPIC}")
    print(f"Intel  : embedded SQLite vector index via IntelAgent")
    print("=" * 60 + "\n")

    # Start the incident worker before connecting so no job is ever dropped.
    worker = threading.Thread(target=_incident_worker, name="aes-incident-worker", daemon=True)
    worker.start()
    print("[MONITOR] Incident worker thread started")

    client = make_mqtt_client("aes-monitor-agent")
    configure_mqtt_client(client, role="monitor")
    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = on_disconnect

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
        client.loop_forever()   # blocks here — handles reconnects automatically
    except KeyboardInterrupt:
        print("\n[MONITOR] Stopped.")
        client.disconnect()
    except ConnectionRefusedError:
        print(f"[MONITOR] Cannot connect to Mosquitto at {BROKER_HOST}:{BROKER_PORT}")
        print("[MONITOR] Is Mosquitto running? Check: sudo systemctl status mosquitto")
        sys.exit(1)

if __name__ == "__main__":
    main()
