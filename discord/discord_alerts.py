"""
AES — Discord Alerts
Posts incident alerts and Hermes learning updates to #aes-alerts.

Win condition #3: live Discord alert firing.

Two alert types:
  post_incident_alert()   — fires on every confirmed anomaly
  post_learning_update()  — fires when Hermes deploys a new detection rule (Solution 3)

Usage:
  from discord_alerts import post_incident_alert, post_learning_update
"""

import time
import requests
import os

from skills.schema import Skill


# ─── INCIDENT ALERT ──────────────────────────────────────────────────────────

def post_incident_alert(
    incident_id:   str,
    device_id:     str,
    device_model:  str,
    attack:        str,
    cve_id:        str,
    cvss:          str,
    solution_track: int,
    action:        str,
    gate1:         str = "PENDING",
    gate2:         str = "PENDING",
    latency_ms:    int = 0,
    status:        str = "OPEN",
) -> bool:
    """
    Posts a structured incident alert to #aes-alerts.
    Matches the format defined in AGENTS.md exactly.
    Returns True if posted successfully.
    """
    msg = (
        f"🚨 **INCIDENT ALERT**\n"
        f"─────────────────────────\n"
        f"**Device:**   {device_id} ({device_model})\n"
        f"**Attack:**   {attack}\n"
        f"**CVE:**      {cve_id} | Severity: {cvss}\n"
        f"**Solution:** {solution_track}\n"
        f"**Action:**   {action}\n"
        f"**Gate 1:**   {gate1}\n"
        f"**Gate 2:**   {gate2}\n"
        f"**Latency:**  {latency_ms}ms\n"
        f"**Status:**   {status}\n"
        f"─────────────────────────\n"
        f"*Incident ID: {incident_id}*"
    )
    return _post(msg)


# ─── HERMES LEARNING UPDATE ──────────────────────────────────────────────────

def post_learning_update(skill: Skill, pending_approval: bool = True) -> bool:
    """
    Posts a Solution 3 learning update to #aes-alerts.

    pending_approval=True  → proposal message asking for ✅ (called by HITL after sandbox passes)
    pending_approval=False → deployment confirmation (called by HITL after inject succeeds)
    """
    import json as _json

    if pending_approval:
        msg = (
            f"🔁 **HERMES LEARNING UPDATE — APPROVAL REQUIRED**\n"
            f"─────────────────────────\n"
            f"**Skill ID:** `{skill.skill_id}` (v{skill.version})\n"
            f"**Incident:** {skill.incident_id}\n"
            f"**CVE:** {skill.cve_id}\n"
            f"**Attack:** {skill.attack_signature[:120]}\n"
            f"**Benchmark:** {skill.benchmark.summary()}\n"
            f"─────────────────────────\n"
            f"**Proposed Params:**\n"
            f"```json\n{_json.dumps(skill.params, indent=2)}\n```\n"
            f"**Change:** {skill.diff}\n"
            f"─────────────────────────\n"
            f"To deploy: `python3 -m skills.hitl approve {skill.skill_id}`\n"
            f"To reject: `python3 -m skills.hitl reject {skill.skill_id}`"
        )
    else:
        msg = (
            f"✅ **SKILL DEPLOYED** — `{skill.skill_id}` (v{skill.version})\n"
            f"─────────────────────────\n"
            f"**Approved by:** {skill.approved_by or 'operator'}\n"
            f"**Benchmark:** {skill.benchmark.summary()}\n"
            f"**Incident:** {skill.incident_id}\n"
            f"**Params now active:** `{_json.dumps(skill.params)}`\n"
            f"─────────────────────────"
        )
    return _post(msg)


# ─── FLEET STATUS ─────────────────────────────────────────────────────────────

def post_fleet_status(device_statuses: dict) -> bool:
    """
    Posts current fleet state. Called by /aes status slash command.
    device_statuses: {device_id: {"status": "clean/anomaly", "last_seen": timestamp}}
    """
    lines = ["📡 **AES Fleet Status**\n─────────────────────────"]
    for device_id, info in device_statuses.items():
        icon = "🟢" if info.get("status") == "clean" else "🔴"
        lines.append(f"{icon} **{device_id}** — {info.get('status', 'unknown')} | last seen {info.get('last_seen', 'N/A')}")
    lines.append("─────────────────────────")
    return _post("\n".join(lines))


# ─── INTERNAL ─────────────────────────────────────────────────────────────────

def _post(content: str) -> bool:
    """
    Send a message to the Discord webhook. Returns True on success.
    Hardened (audit finding M3):
      - Skips cleanly if no webhook is configured (no crash on empty URL).
      - Truncates to Discord's 2000-char limit.
      - Honors HTTP 429 rate limiting with the server's retry_after, up to 3 tries.
    """
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")
    if not webhook_url:
        print("[DISCORD] No DISCORD_WEBHOOK_URL configured — skipping post")
        return False

    if len(content) > 2000:
        content = content[:1990] + "\n…(truncated)"

    for attempt in range(3):
        try:
            r = requests.post(webhook_url, json={"content": content}, timeout=10)
            if r.status_code in (200, 204):
                return True
            if r.status_code == 429:
                try:
                    retry_after = float(r.json().get("retry_after", 1.0))
                except Exception:
                    retry_after = 1.0
                print(f"[DISCORD] Rate limited — retrying in {retry_after:.1f}s")
                time.sleep(min(retry_after, 5.0))
                continue
            print(f"[DISCORD] Post failed — HTTP {r.status_code}: {r.text}")
            return False
        except requests.exceptions.RequestException as e:
            print(f"[DISCORD] Post failed — {e}")
            return False
    print("[DISCORD] Post failed — rate limited after 3 attempts")
    return False


# ─── QUICK TEST ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Testing Discord alerts...")

    # Test 1: incident alert
    ok = post_incident_alert(
        incident_id    = "INC-20260530-120000-esp32-cam-01",
        device_id      = "esp32-cam-01",
        device_model   = "ESP32-CAM",
        attack         = "ANOMALY DETECTED — cpu +299% above normal, packet_rate +953% above normal",
        cve_id         = "CVE-2021-34173",
        cvss           = "HIGH (9.8)",
        solution_track = 1,
        action         = "OTA_PATCH_PENDING",
        gate1          = "PENDING",
        gate2          = "PENDING",
        latency_ms     = 312,
        status         = "OPEN",
    )
    print(f"Incident alert: {'✅ sent' if ok else '❌ failed'}")

    time.sleep(1)

    # Test 2: learning update (approval pending). post_learning_update takes a
    # Skill, so build a minimal one — the old kwargs signature never existed.
    demo_skill = Skill(
        incident_id      = "INC-20260530-120000-esp32-cam-01",
        cve_id           = "CVE-2021-34173",
        attack_signature = "cpu +299%, packet_rate +953% — Mirai-style flood",
        params           = {"deviation_threshold": 0.35, "simultaneous_threshold": 2},
        diff             = "params: {threshold 0.5} → {threshold 0.35}",
    )
    ok = post_learning_update(demo_skill, pending_approval=True)
    print(f"Learning update: {'✅ sent' if ok else '❌ failed'}")
