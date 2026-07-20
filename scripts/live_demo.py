"""
AES — live demo driver
======================
Feeds the FastAPI backend (dashboard/app.py) with a connected, continuously-updating
fleet so the web app (run with NEXT_PUBLIC_DEMO=0) shows LIVE data via /api/devices and
/api/state. This is NOT the MQTT pipeline (no broker required) — it's a self-contained
simulator that writes the same artifacts the real pipeline writes:

  config/fleet_status.json   ← refreshed every 2s (4 connected devices, jittering metrics)
  aes_incidents.jsonl        ← seeded incidents (with verdict + patch) for the theaters
  config/skills.jsonl        ← one PENDING_HITL skill for the Self-Improvement page

Run:  python scripts/live_demo.py
Stop: Ctrl-C
"""
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def _load_env():
    """Minimal .env loader — pulls DISCORD_WEBHOOK_URL (and friends) into the
    environment so post_incident_alert() can fire, without a dotenv dependency."""
    env = REPO / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


_load_env()

# Discord incident alert — optional; never let its absence break the demo loop.
try:
    from discord.discord_alerts import post_incident_alert
except Exception:
    post_incident_alert = None

CONF = REPO / "config"
FLEET = CONF / "fleet_status.json"
SKILLS = CONF / "skills.jsonl"
INCIDENTS = REPO / "aes_incidents.jsonl"
DEMO_CTL = CONF / "demo_control.json"

# Everything starts (and stays) normal — only esp32-cam-01 is demoed, on demand,
# via the attack button on its device screen (see DEMO_CAM / the demo_* helpers).
DEVICES = [
    {"id": "esp32-cam-01", "status": "clean", "base": {"cpu": 21, "mem": 38, "pkt": 47, "conn": 1}},
    {"id": "esp32-cam-02", "status": "clean", "base": {"cpu": 21, "mem": 40, "pkt": 47, "conn": 1}},
    {"id": "esp32-cam-03", "status": "clean", "base": {"cpu": 23, "mem": 40, "pkt": 51, "conn": 1}},
    {"id": "tapo-c200-01", "status": "clean", "base": {"cpu": 16, "mem": 44, "pkt": 28, "conn": 2}},
]

DEMO_CAM = "esp32-cam-01"

# The cam-01 demo timeline: seconds-since-click → (pipeline stage, device status).
# One click runs the whole story; it auto-advances through the SAME stage keys the
# real pipeline emits, in order — Monitor (monitor_agent) → Intel + Hermes
# (monitor_agent_mqtt) → Response/OpenClaw (response_agent) → resolved — so the
# Incident Theater bus lights up one node at a time, exactly like a live incident.
DEMO_TIMELINE = [
    (0.0,  "monitor_logged",  "attack"),   # Monitor logged the anomaly  → Intel active
    (1.6,  "intel_done",      "attack"),   # RAG matched the CVE          → Hermes active
    (3.2,  "hermes_done",     "attack"),   # Hermes verdict written       → Response active
    (4.8,  "vuln_confirmed",  "attack"),   # Response routing the verdict → OpenClaw
    (6.4,  "patch_generated", "attack"),   # Hermes unified diff
    (8.0,  "gate1_running",   "attack"),   # Semgrep scanning
    (9.6,  "gate1_passed",    "attack"),   # Gate 1 PASS
    (11.2, "flashing",        "attack"),   # OTA flash ota_1
    (12.8, "validating",      "attack"),   # 30s self-validate window
    (14.4, "boot_confirmed",  "clean"),    # patch live → device back to baseline
]

# Ordered stage names, for index-based gating of verdict/patch/gates fields.
STAGE_SEQUENCE = [s for _, s, _ in DEMO_TIMELINE]
_IDX = {s: i for i, s in enumerate(STAGE_SEQUENCE)}


def _demo_phase():
    """(phase, elapsed_seconds). phase is 'attack' once the button is clicked, else 'normal'."""
    ctl = {}
    try:
        ctl = json.loads(DEMO_CTL.read_text())
    except Exception:
        pass
    if ctl.get("phase") == "attack":
        return "attack", max(0.0, time.time() - float(ctl.get("t0", time.time())))
    return "normal", 0.0


def _demo_stage(elapsed):
    """Stage + device status for the current point in the cam-01 attack timeline."""
    stage, status = DEMO_TIMELINE[0][1], DEMO_TIMELINE[0][2]
    for t, stg, st in DEMO_TIMELINE:
        if elapsed >= t:
            stage, status = stg, st
    return stage, status

DIFF = (
    "@@ esp32-cam/main/handler.c @@\n"
    "  void on_packet(char *buf) {\n"
    "-     strcpy(dest, buf);\n"
    "+     strlcpy(dest, buf, sizeof(dest));\n"
    "      process(dest);\n"
    "  }"
)


def _target(status, b):
    if status == "attack":
        return {"cpu": 88, "mem": b["mem"] * 1.45, "pkt": 512, "conn": 47}
    if status == "elevated":
        return {"cpu": b["cpu"] * 2.4, "mem": b["mem"] * 1.15, "pkt": b["pkt"] * 3.2, "conn": b["conn"] + 6}
    if status == "warming":
        return {"cpu": b["cpu"] * 1.6, "mem": b["mem"] * 1.05, "pkt": b["pkt"] * 1.8, "conn": b["conn"] + 2}
    return {"cpu": b["cpu"], "mem": b["mem"], "pkt": b["pkt"], "conn": b["conn"]}


def _jit(v, amt):
    return max(0.0, v * (1 + (random.random() - 0.5) * amt))


def write_fleet(demo_status=None):
    """Write the fleet snapshot. `demo_status` overrides esp32-cam-01's runtime
    status (the rest stay clean) so the attack button can drive that one device."""
    now = datetime.now().strftime("%H:%M:%S")
    out = {}
    for d in DEVICES:
        status = demo_status if (d["id"] == DEMO_CAM and demo_status) else d["status"]
        t = _target(status, d["base"])
        amt = 0.10 if status == "clean" else 0.08 if status == "attack" else 0.14
        out[d["id"]] = {
            "status": status,
            "cpu_percent": round(min(100, _jit(t["cpu"], amt)), 1),
            "memory_percent": round(min(100, _jit(t["mem"], amt)), 1),
            "packet_rate": round(_jit(t["pkt"], amt), 1),
            "connection_count": int(round(_jit(t["conn"], amt))),
            "last_seen": now,
        }
    FLEET.write_text(json.dumps(out, indent=2))


def base_incidents():
    return [
        {
            "incident_id": "INC-2138-cam02",
            "timestamp": "21:38:41",
            "device_id": "esp32-cam-02",
            "device_model": "ESP32-CAM",
            "solution_track": 1,
            "confidence": 0.97,
            "reason": "cpu +299%, packet_rate +953% — 2 rules fired simultaneously",
            "deviations": {"cpu_percent": 2.99, "packet_rate": 9.53, "connection_count": 14.66},
            "baseline": {"cpu_percent": 21, "packet_rate": 47, "connection_count": 1, "memory_percent": 38},
            "status": "RESOLVED",
            "resolved_at": "21:38:43",
            "latency_ms": 312,
            "cve_id": "CVE-2021-34173",
            "cve_severity": "HIGH",
            "cve_score": 9.8,
            "verdict": {
                "solution_track": 1,
                "action": "PATCH_OTA",
                "cve_id": "CVE-2021-34173",
                "confidence": 0.91,
                "reasoning": "ESP32 heap overflow consistent with a Mirai C2 beacon. OTA patch hardens the vulnerable strcpy.",
            },
            "patch": {
                "diff": DIFF,
                "gates": [
                    {"rule_id": "CWE-119", "label": "buffer overflow", "passed": True, "note": "resolved"},
                    {"rule_id": "CWE-416", "label": "use-after-free", "passed": True},
                    {"rule_id": "CWE-78", "label": "command injection", "passed": True},
                    {"rule_id": "CWE-798", "label": "hardcoded creds", "passed": True},
                ],
            },
        },
        {
            "incident_id": "INC-2140-tapo",
            "timestamp": "21:40:05",
            "device_id": "tapo-c200-01",
            "device_model": "TP-Link Tapo C200",
            "solution_track": 2,
            "confidence": 0.74,
            "reason": "packet_rate +242%, connection_count +300% — sustained low-and-slow",
            "deviations": {"packet_rate": 2.42, "connection_count": 3.0, "cpu_percent": 1.44},
            "baseline": {"cpu_percent": 16, "packet_rate": 28, "connection_count": 2, "memory_percent": 44},
            "status": "MANUAL_REVIEW",
            "cve_id": "CVE-2021-4045",
            "cve_severity": "CRITICAL",
            "cve_score": 9.8,
            "verdict": {
                "solution_track": 2,
                "action": "BLOCK_FIREWALL",
                "cve_id": "CVE-2021-4045",
                "confidence": 0.78,
                "reasoning": "Closed firmware — cannot patch. Quarantine at the gateway via a 3-source whitelist.",
            },
            "patch": {
                "whitelist": [
                    "allow  tapo-c200-01 -> 192.168.1.1:443    cloud heartbeat (manufacturer spec)",
                    "allow  tapo-c200-01 -> 192.168.1.10:554   RTSP to NVR (fresh-flash baseline)",
                    "deny   tapo-c200-01 -> 0.0.0.0/0          default-deny everything else",
                ],
            },
        },
    ]


def cam01_incident(stage, status):
    """The live esp32-cam-01 incident for the demo, at the given pipeline stage.
    OPEN while the patch is in flight; RESOLVED once the OTA boot is confirmed."""
    resolved = stage == "boot_confirmed"
    idx = _IDX.get(stage, 0)
    now = datetime.now().strftime("%H:%M:%S")
    inc = {
        "incident_id": "INC-DEMO-cam01",
        "timestamp": now,
        "device_id": DEMO_CAM,
        "device_model": "ESP32-CAM",
        "solution_track": 1,
        "confidence": 0.97,
        "reason": "cpu +299%, packet_rate +953% — 2 rules fired simultaneously",
        "deviations": {"cpu_percent": 2.99, "packet_rate": 9.53, "connection_count": 14.66},
        "baseline": {"cpu_percent": 21, "packet_rate": 47, "connection_count": 1, "memory_percent": 38},
        "status": "RESOLVED" if resolved else "OPEN",
        "latency_ms": 312,
        "cve_id": "CVE-2021-34173",
        "cve_severity": "HIGH",
        "cve_score": 9.8,
        "stage": stage,
    }
    # Each field appears only once its node in the bus has actually produced it —
    # so Intel → Hermes → Response/OpenClaw light up one at a time, not all at once.
    if idx >= _IDX["hermes_done"]:
        inc["verdict"] = {
            "solution_track": 1,
            "action": "PATCH_OTA",
            "cve_id": "CVE-2021-34173",
            "confidence": 0.91,
            "reasoning": "ESP32 heap overflow consistent with a Mirai C2 beacon. OTA patch hardens the vulnerable strcpy.",
        }
    # Patch diff appears once Hermes has generated it; Gate 1 results appear only
    # after Semgrep has actually run — before that the theater shows them pending.
    gates_done = idx >= _IDX["gate1_passed"]
    patch = {}
    if idx >= _IDX["patch_generated"]:
        patch["diff"] = DIFF
    if gates_done:
        patch["gates"] = [
            {"rule_id": "CWE-119", "label": "buffer overflow", "passed": True, "note": "resolved"},
            {"rule_id": "CWE-416", "label": "use-after-free", "passed": True},
            {"rule_id": "CWE-78", "label": "command injection", "passed": True},
            {"rule_id": "CWE-798", "label": "hardcoded creds", "passed": True},
        ]
    if patch:
        inc["patch"] = patch
    if resolved:
        inc["resolved_at"] = now
    return inc


def write_incidents(extra=None):
    rows = base_incidents()
    if extra:
        rows.append(extra)
    # Stamp every fabricated theater incident so the skill sandbox can exclude
    # them from its real attack corpus (REVIEW P1-6).
    for r in rows:
        r["demo"] = True
    INCIDENTS.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def _skill(sid, ver, ts, thr, det, status):
    return {
        "skill_id": sid,
        "version": ver,
        "created_at": ts,
        "incident_id": "INC-2138-cam02",
        "cve_id": "CVE-2021-34173",
        "device_type": "ESP32-CAM",
        "attack_signature": "cpu + packet_rate simultaneous spike",
        "params": {"deviation_threshold": thr, "simultaneous_threshold": 2},
        "diff": f"deviation_threshold -> {thr}",
        "benchmark": {
            "detection_rate": det,
            "false_positive_rate": 0.04,
            "latency_ms": 312.0,
            "sample_size": 240,
            "normal_sample_size": 600,
        },
        "status": status,
        "approved_by": "auto" if status == "INJECTED" else None,
        "approved_at": ts if status == "INJECTED" else None,
    }


def seed_skills():
    # three deployed skills (detection rate climbing 80 -> 95) + one pending for approval
    skills = [
        _skill("skill-001", 1, "2026-06-15T10:00:00+00:00", 0.45, 0.84, "INJECTED"),
        _skill("skill-002", 1, "2026-06-16T10:00:00+00:00", 0.40, 0.91, "INJECTED"),
        _skill("skill-003", 1, "2026-06-17T10:00:00+00:00", 0.37, 0.95, "INJECTED"),
        _skill("skill-7f3a2c1b", 2, "2026-06-17T21:38:50+00:00", 0.35, 0.91, "PENDING_HITL"),
    ]
    SKILLS.write_text("\n".join(json.dumps(s) for s in skills) + "\n")


def fire_discord(inc):
    """Post the live #aes-alerts incident alert (win condition #3). Best-effort."""
    if not post_incident_alert:
        return
    try:
        ok = post_incident_alert(
            incident_id=inc["incident_id"],
            device_id=inc["device_id"],
            device_model=inc["device_model"],
            attack=inc["reason"],
            cve_id=inc["cve_id"],
            cvss=f'{inc["cve_severity"]} {inc["cve_score"]}',
            solution_track=inc["solution_track"],
            action=inc["verdict"]["action"],
            gate1="PASS",
            gate2="SIMULATED",
            latency_ms=inc["latency_ms"],
            status=inc["status"],
        )
        print(f"[DISCORD] incident alert {'posted' if ok else 'skipped'}")
    except Exception as e:
        print(f"[DISCORD] alert error: {e}")


def main():
    CONF.mkdir(exist_ok=True)
    if not DEMO_CTL.exists():
        DEMO_CTL.write_text(json.dumps({"phase": "normal"}))
    seed_skills()
    write_incidents()
    print(f"AES live demo driver -> {FLEET} (Ctrl-C to stop)")
    last = None
    while True:
        phase, elapsed = _demo_phase()
        if phase == "attack":
            stage, status = _demo_stage(elapsed)
            write_fleet(demo_status=status)
            snap = (phase, stage)
            if snap != last:
                inc = cam01_incident(stage, status)
                write_incidents(inc)
                # Discord fires once, on the terminal branch — same as the real
                # pipeline (alert posted when the incident reaches a final state).
                if stage == "boot_confirmed":
                    fire_discord(inc)
                last = snap
        else:
            write_fleet()
            if last is not None:
                write_incidents()   # demo reset → drop the cam-01 incident
                last = None
        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
