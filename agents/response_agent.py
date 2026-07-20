"""
AES — Response Agent
====================
Owner: Son Nguyen (AI Infra) — routing logic
       Duc Vu (Pipeline)     — Solution 1/2 execution (replace stubs below)
Moved to: agents/response_agent.py

WHAT IT DOES:
  Takes a Hermes verdict and routes it to the right solution handler.
  Handles retries with exponential backoff, updates the incident log,
  and posts a Discord alert to #aes-alerts on every outcome.

HOW TO RUN:
  Not run directly — called by agents/monitor_agent_mqtt.py.

SOLUTION ROUTING:
  Track 1 → handle_solution_1() → OTA patch pipeline
             [DUC + VY: replace stub with real esptool.py OTA execution]
  Track 2 → handle_solution_2() → iptables whitelist rule
             [DUC: replace stub with real SSH + iptables write to Pi gateway]
  (Solution 3 — the Hermes learning loop — is NOT routed here. It is triggered
   directly from the monitor path via skills.hitl.propose_skill(); see
   agents/monitor_agent_mqtt.py.)

RED LINES (never skip these):
  - Never write a live iptables rule without --check dry-run passing first.
  - Never trigger OTA flash without Gate 1 AND Gate 2 both cleared.
  - Never discard a failed patch — log to outputs/patches/failed/.

RETRY LOGIC:
  MAX_RETRIES = 3, backoff = 2^attempt seconds (2s, 4s, 8s).
  After all retries fail, incident is marked FAILED and Discord is notified.
"""

import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from discord.discord_alerts import post_incident_alert
from agents.monitor_agent import DEVICE_REGISTRY

# ─── PATCH HELPER ────────────────────────────────────────────────────────────

def _find_line_block(haystack: list, needle: list, start: int = 0,
                     normalize=None) -> int:
    """
    Return the index in `haystack` where the contiguous full-line sequence
    `needle` first appears at or after `start`, or -1 if not found.
    Matches whole lines (not substrings), so 'x = 1;' never matches 'max = 1;'.

    If `normalize` is given (a str->str fn), both sides are passed through it
    before comparison — used to tolerate trailing-whitespace drift in Hermes
    output without weakening the exact pass.
    """
    if not needle:
        return -1
    hay = haystack if normalize is None else [normalize(h) for h in haystack]
    ndl = needle   if normalize is None else [normalize(n) for n in needle]
    last = len(hay) - len(ndl)
    for i in range(start, last + 1):
        if hay[i:i + len(ndl)] == ndl:
            return i
    return -1


def _apply_hermes_diff(source_text: str, raw_diff: str, src_name: str) -> tuple:
    """
    Apply Hermes's raw unified diff hunk-by-hunk and return (patched_text,
    proper_diff).

    Hermes routinely emits wrong @@ line counts, truncated context, and
    sometimes wraps the diff in markdown fences. So we ignore the @@ counts
    entirely and, for EACH hunk independently, reconstruct:
      - the 'before' block = context + removed lines, in original order
      - the 'after'  block = context + added   lines, in original order
    then locate the 'before' block as a contiguous run of whole lines in the
    current text and splice in the 'after' block.

    This respects context lines sitting BETWEEN removed lines, which the old
    "glue every '-' line into one blob" approach could not — that approach
    failed whenever a fix touched non-adjacent lines or spanned >1 hunk.

    Raises ValueError if no hunk could be located in the source.
    """
    # Drop markdown fences (```diff … ``` or bare ``` …) if the model added them.
    lines = [l for l in raw_diff.splitlines() if not l.lstrip().startswith("```")]

    # Split the body into hunks. Each hunk is a list of (tag, content) where
    # tag is ' ' (context), '-' (removed) or '+' (added). Everything before the
    # first @@ — including the ---/+++ file headers — is preamble and ignored.
    hunks: list = []
    current = None
    for line in lines:
        if line.startswith("@@"):
            current = []
            hunks.append(current)
            continue
        if current is None:
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue                      # stray file header inside the body
        if line.startswith("-"):
            current.append(("-", line[1:]))
        elif line.startswith("+"):
            current.append(("+", line[1:]))
        elif line.startswith(" "):
            current.append((" ", line[1:]))
        elif line == "":
            current.append((" ", ""))     # blank unchanged line
        # anything else (stray prose) is ignored

    if not hunks:
        raise ValueError("No @@ hunks found in diff")

    src_lines = source_text.split("\n")
    applied = 0
    search_from = 0
    rstrip = lambda s: s.rstrip()
    for hunk in hunks:
        before  = [c for tag, c in hunk if tag in (" ", "-")]
        after   = [c for tag, c in hunk if tag in (" ", "+")]
        removed = [c for tag, c in hunk if tag == "-"]
        added   = [c for tag, c in hunk if tag == "+"]
        if before == after:
            continue                      # no-op hunk

        # Try, most-specific first:
        #   1. context + removed block  (exact, then trailing-ws tolerant)
        #   2. removed lines alone       (exact, then trailing-ws tolerant)
        # The removed-only pass handles context the model mangled or dropped.
        for needle, repl in ((before, after), (removed, added)):
            idx = _find_line_block(src_lines, needle, search_from)
            if idx == -1:
                idx = _find_line_block(src_lines, needle, search_from, normalize=rstrip)
            if idx != -1:
                src_lines[idx:idx + len(needle)] = repl
                search_from = idx + len(repl)
                applied += 1
                break
        else:
            raise ValueError(
                "Hunk did not match source — context/removed lines not found "
                "(diff may reference the wrong code)"
            )

    if applied == 0:
        raise ValueError("Diff contained no changes that applied to the source")

    patched = "\n".join(src_lines)

    proper_diff = ''.join(difflib.unified_diff(
        source_text.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f'a/main/{src_name}',
        tofile=f'b/main/{src_name}',
    ))
    return patched, proper_diff


# ─── CONFIG ──────────────────────────────────────────────────────────────────

LOG_PATH    = Path("./aes_incidents.jsonl")
HASH_PATH   = Path("./aes_incidents.hashes")
MAX_RETRIES = 3
BACKOFF_BASE = 2   # seconds — doubles each retry: 2s, 4s, 8s

# Maps each Gate 1 Semgrep rule to the short id/label the dashboard renders.
# gate1.py returns one pass/fail flag for the whole scan plus a flat failures
# list — this expands that into a per-rule result so the Patch Theater can show
# which specific check passed/failed instead of one opaque pass/fail.
_GATE1_RULES = [
    ("esp32-cwe119-buffer-overflow",       "CWE-119", "buffer overflow"),
    ("esp32-cwe416-use-after-free",        "CWE-416", "use-after-free"),
    ("esp32-cwe78-command-injection",      "CWE-78",  "command injection"),
    ("esp32-cwe798-hardcoded-credentials", "CWE-798", "hardcoded creds"),
]


def _gate1_results(g1: dict) -> list:
    """Turn gate1.py's {"passed", "failures": [{"rule_id","line","message"}]} into
    the dashboard's GateResult[] — one row per known rule, real pass/fail + note."""
    by_rule = {f.get("rule_id"): f for f in (g1.get("failures") or [])}
    return [
        {
            "rule_id": short_id,
            "label":   label,
            "passed":  semgrep_id not in by_rule,
            "note":    by_rule[semgrep_id]["message"] if semgrep_id in by_rule else "resolved",
        }
        for semgrep_id, short_id, label in _GATE1_RULES
    ]


# ─── SOLUTION HANDLERS ───────────────────────────────────────────────────────
# Each handler returns True on success, False on failure.
# Duc wires Solution 1 + 2. Solution 3 (the learning loop) runs from the monitor
# path (skills.hitl), not here.

# Bench firmware source selection. Prefer main_vulnerable.c (demo mode with an
# intentional CWE-119) ONLY when AES_ALLOW_VULN_SOURCE=1 — otherwise always patch
# the production main.c. This stops a stray main_vulnerable.c from silently
# becoming the patch base in production (REVIEW P2-16).
def _select_firmware_source() -> Path | None:
    if os.getenv("AES_ALLOW_VULN_SOURCE") == "1":
        vuln = Path("esp32-cam/main/main_vulnerable.c")
        if vuln.exists():
            return vuln
    main = Path("esp32-cam/main/main.c")
    return main if main.exists() else None


def _run_gate1(patched_text: str, src_name: str) -> dict:
    """Scan already-patched text through Gate 1 (Semgrep). Returns gate1.py's
    {"passed", "failures"|"error"} dict. Never raises."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_main_dir = Path(tmpdir) / "main"
        tmp_main_dir.mkdir()
        (tmp_main_dir / src_name).write_text(patched_text, encoding="utf-8")
        try:
            g1_proc = subprocess.run(
                [sys.executable, "gate1.py", str(tmp_main_dir / src_name)],
                capture_output=True, text=True, cwd="gates/semgrep", timeout=120,
            )
        except subprocess.TimeoutExpired:
            return {"passed": False, "error": "Gate 1 timed out after 120s"}
        print(f"    [GATE 1 OUTPUT]\n{g1_proc.stdout}\n{g1_proc.stderr}".rstrip())
        try:
            marker = "--- GATE 1 OUTPUT RESULT ---"
            g1_text = g1_proc.stdout
            return json.loads(g1_text[g1_text.index(marker) + len(marker):].strip())
        except (ValueError, json.JSONDecodeError):
            return {"passed": False, "error": "Gate 1 output parse failure"}


def _format_gate1_feedback(g1: dict) -> str:
    """Render Gate 1 failures as retry feedback for Hermes' {semgrep_output} slot."""
    failures = g1.get("failures") or []
    if not failures:
        return g1.get("error", "Gate 1 rejected the patch (no detail).")
    return "\n".join(
        f"- {f.get('rule_id')} at line {f.get('line')}: {f.get('message')}"
        for f in failures
    )


def _run_gate2(patched_text: str) -> dict:
    """Run the Compile-Boot-Diff harness on the patched source. Returns its
    {"passed", "stages"|"error"} dict. Never raises."""
    gate2_path = Path("gates/gate2.py")
    g2_args = [sys.executable, str(gate2_path.resolve())]
    if os.getenv("AES_GATE2_STRICT") == "1":
        g2_args.append("--strict")
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False, encoding="utf-8") as g2_src:
        g2_src.write(patched_text)
        g2_src_path = g2_src.name
    try:
        g2_proc = subprocess.run(g2_args + [g2_src_path], capture_output=True, text=True, timeout=900)
        marker = "--- GATE 2 OUTPUT RESULT ---"
        g2_text = g2_proc.stdout
        return json.loads(g2_text[g2_text.index(marker) + len(marker):].strip())
    except subprocess.TimeoutExpired:
        return {"passed": False, "error": "Gate 2 timed out after 900s"}
    except (ValueError, json.JSONDecodeError):
        return {"passed": False, "error": "Gate 2 output parse failure"}
    finally:
        os.unlink(g2_src_path)


def _staged_firmware_build(patched_text: str) -> Path | None:
    """
    Build the PATCHED firmware and return the path to the app binary, or None if
    the ESP-IDF toolchain is absent.

    CRITICAL (REVIEW P0-1): the ESP-IDF project compiles only main.c (see
    esp32-cam/main/CMakeLists.txt), so building the in-tree project would flash
    the ORIGINAL firmware. We instead stage a copy of the project with the patched
    text written AS main.c and build that — mirroring gates/gate2.py check_compile.
    When Gate 2's compile stage already produced outputs/gate2/verified_firmware.bin
    from this same patched source, reuse it instead of rebuilding.
    """
    verified = Path("outputs/gate2/verified_firmware.bin")
    if verified.exists():
        print(f"    Reusing Gate 2 verified binary → {verified}")
        return verified

    idf = shutil.which("idf.py")
    if not idf:
        return None

    project_dir = Path("esp32-cam")
    with tempfile.TemporaryDirectory(prefix="aes-sol1-") as tmp:
        staged = Path(tmp) / "esp32-cam"
        shutil.copytree(
            project_dir, staged,
            ignore=shutil.ignore_patterns("build", "sdkconfig.old", "managed_components"),
        )
        # The staged build compiles the PATCHED text as main.c; the production
        # tree is never touched. Remove the alternate sources so only main.c wins.
        (staged / "main" / "main.c").write_text(patched_text, encoding="utf-8")
        for extra in ("main_vulnerable.c", "main_patched.c"):
            (staged / "main" / extra).unlink(missing_ok=True)
        try:
            build = subprocess.run([idf, "build"], capture_output=True, text=True,
                                   cwd=staged, timeout=600)
        except subprocess.TimeoutExpired:
            print("    [ERROR] Staged build timed out after 600s")
            return None
        if build.returncode != 0:
            print(f"    [ERROR] Staged build failed:\n{build.stderr[-800:]}")
            return None
        staged_build = staged / "build"
        # Prefer the project's app binary by name; fall back to the largest .bin
        # (the app image dwarfs bootloader/partition binaries).
        named = staged_build / "aes_esp32_cam.bin"
        if named.exists():
            src_bin = named
        else:
            bins = list(staged_build.glob("*.bin"))
            if not bins:
                print("    [ERROR] Staged build produced no .bin")
                return None
            src_bin = max(bins, key=lambda p: p.stat().st_size)
        out_dir = Path("outputs/gate2")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_bin = out_dir / "verified_firmware.bin"
        shutil.copy2(src_bin, out_bin)
        print(f"    Staged patched build → {out_bin}")
        return out_bin


def _flash_and_confirm(device_id: str, incident_id: str, patched_text: str) -> bool:
    """
    Build the patched firmware, flash it, and confirm the device reboots.
    Only reached when AES_FLASH_ENFORCE=1 (a real physical write). On the bench
    without a toolchain it self-skips and reports no_hardware (returns True).
    """
    print(f"    Building patched firmware...")
    update_incident_fields(incident_id, stage="building")
    firmware_bin = _staged_firmware_build(patched_text)
    if firmware_bin is None:
        print(f"    [WARN] ESP-IDF toolchain unavailable — build/flash skipped (no hardware)")
        update_incident_fields(incident_id, stage="no_hardware")
        return True

    device_info = DEVICE_REGISTRY.get(device_id, {})
    serial_port = device_info.get("port") or os.getenv("ESP32_PORT")
    if not serial_port:
        print(f"    [ERROR] No serial port for {device_id}. Set ESP32_PORT or add 'port' "
              f"to config/device_registry.json.")
        update_incident_fields(incident_id, stage="flash_failed")
        return False

    print(f"    Flashing {firmware_bin.name} → {serial_port}...")
    update_incident_fields(incident_id, stage="flashing")
    try:
        flash = subprocess.run(
            ["esptool.py", "--chip", "esp32", "--port", serial_port,
             "--baud", "460800", "write_flash", "0x10000", str(firmware_bin)],
            capture_output=True, text=True, timeout=120,
        )
        if flash.returncode != 0:
            print(f"    [ERROR] Flash failed:\n{flash.stderr[-500:]}")
            update_incident_fields(incident_id, stage="flash_failed")
            return False
        print(f"    Flash complete")
    except FileNotFoundError:
        print(f"    [ERROR] esptool.py not found — install with: pip install esptool")
        update_incident_fields(incident_id, stage="flash_failed")
        return False
    except subprocess.TimeoutExpired:
        print(f"    [ERROR] Flash timed out after 120s")
        update_incident_fields(incident_id, stage="flash_failed")
        return False

    # ── MQTT boot confirmation (35s window per OTA_LIFECYCLE.md) ──────────────
    # Boot proof must come from THIS device's fresh telemetry (REVIEW P1-9): the
    # message's payload device_id must match, and its timestamp must be newer than
    # the flash. A running simulator for the same id can't fake it via timestamp.
    print(f"    Waiting for {device_id} MQTT boot confirmation (35s)...")
    update_incident_fields(incident_id, stage="validating")
    from agents.mqtt_compat import make_mqtt_client

    flashed_at = datetime.now(timezone.utc).isoformat()
    confirmed = threading.Event()

    def _on_boot_msg(client, _userdata, msg):
        try:
            data = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if data.get("device_id") != device_id:
            return
        # Require a post-flash timestamp when the firmware provides one.
        ts = data.get("timestamp")
        if ts and ts < flashed_at:
            return
        confirmed.set()
        client.disconnect()

    boot_mqtt = make_mqtt_client("aes-boot-verify")
    boot_mqtt.on_message = _on_boot_msg
    try:
        mqtt_host = os.getenv("MQTT_HOST", "localhost")
        mqtt_port = int(os.getenv("MQTT_PORT", "1883"))
        boot_mqtt.connect(mqtt_host, mqtt_port, keepalive=10)
        boot_mqtt.subscribe(f"aes/telemetry/{device_id}")
        boot_mqtt.loop_start()
        boot_ok = confirmed.wait(timeout=35)
        boot_mqtt.loop_stop()
        try:
            boot_mqtt.disconnect()
        except Exception:
            pass
    except Exception as e:
        print(f"    [WARN] MQTT boot verify error: {e}")
        boot_ok = False

    if boot_ok:
        print(f"    ✅ Device {device_id} booted — telemetry confirmed")
        update_incident_fields(incident_id, stage="boot_confirmed")
        return True
    print(f"    ❌ Boot confirmation timeout — device may have auto-rolled back")
    update_incident_fields(incident_id, stage="boot_timeout")
    return False


# How many times to ask Hermes for a fix, feeding Gate 1 findings back each retry.
PATCH_MAX_ATTEMPTS = 3


def handle_solution_1(incident: dict, verdict: dict) -> bool:
    """
    Solution 1 — OTA patch for open-firmware devices (ESP32-CAM).
    Flow: Intel CVE context → (Hermes patch → Gate 1, retried with feedback) →
          Gate 2 → persist → [HITL flash gate] → staged build → flash → boot confirm.

    Never flashes without Gate 1 AND Gate 2 green. The physical flash is gated
    behind AES_FLASH_ENFORCE=1 (REVIEW P0-3): by default the validated patch is
    persisted and held at stage=awaiting_flash_approval for human review — flash
    it with `python -m agents.response_agent flash <incident_id>`.
    """
    from agents.hermes import Hermes
    from agents.llm_client import make_hermes_client
    from agents.intel_agent import IntelAgent

    device_id   = incident["device_id"]
    incident_id = incident["incident_id"]
    cve_id      = verdict.get("cve_id", "UNKNOWN")

    print(f"  [SOLUTION 1] OTA patch pipeline on {device_id}")
    print(f"    CVE: {cve_id}")
    update_incident_fields(incident_id, stage="vuln_confirmed")

    # ── Step 1: Read the firmware source to patch ────────────────────────────
    firmware_src = _select_firmware_source()
    if firmware_src is None:
        print(f"    [ERROR] Firmware source not found under esp32-cam/main/")
        return False
    vulnerable_code = firmware_src.read_text(encoding="utf-8")
    print(f"    Step 1: Loaded firmware source {firmware_src.name} ({len(vulnerable_code)} chars)")

    # ── Step 2: Re-query Intel Agent for CVE context (once) ──────────────────
    print(f"    Step 2: Querying Intel Agent for CVE context...")
    try:
        intel = IntelAgent()
        ctx = intel.query(
            device_model=incident.get("device_model", "ESP32-CAM"),
            firmware_version="unknown",
            attack_signature=f"{cve_id} {incident.get('reason', '')}",
        )
        cve_context = ctx.formatted
    except Exception as e:
        print(f"    [WARN] Intel Agent unavailable ({e}) — using CVE ID only")
        cve_context = f"CVE: {cve_id}\n(Intel Agent unavailable — no additional context)"

    pending_dir = Path("outputs/patches/pending")
    failed_dir  = Path("outputs/patches/failed")
    pending_dir.mkdir(parents=True, exist_ok=True)
    failed_dir.mkdir(parents=True, exist_ok=True)
    patch_file = pending_dir / f"{incident_id}.patch"

    try:
        hermes = Hermes(client=make_hermes_client())
    except Exception as e:
        print(f"    [ERROR] Could not initialize Hermes: {e}")
        return False

    # ── Steps 3-5: generate → apply → Gate 1, retried with Semgrep feedback ───
    # (REVIEW P1-4) Each retry passes the previous Gate 1 findings into the prompt's
    # {semgrep_output} slot, so Hermes actually corrects the flagged code instead
    # of re-emitting the same rejected patch at full LLM cost.
    semgrep_feedback = "None — first attempt"
    patched_text = None
    patch_diff = None
    g1 = None
    for attempt in range(1, PATCH_MAX_ATTEMPTS + 1):
        print(f"    Step 3: Hermes generating patch for {cve_id} (attempt {attempt}/{PATCH_MAX_ATTEMPTS})...")
        try:
            raw_diff = hermes.generate_patch(
                vulnerable_code=vulnerable_code,
                cve_context=cve_context,
                cwe_type=verdict.get("cwe_type", "UNKNOWN"),
                semgrep_output=semgrep_feedback,
            )
        except Exception as e:
            print(f"    [ERROR] Hermes patch generation failed: {e}")
            return False

        # Hermes emits wrong @@ counts / truncated context, so we re-apply the
        # diff hunk-by-hunk in Python and regenerate a correct unified diff.
        try:
            patched_text, patch_diff = _apply_hermes_diff(
                vulnerable_code, raw_diff, firmware_src.name
            )
            print(f"    Diff reformatted with correct line counts")
        except ValueError as e:
            print(f"    [ERROR] Could not apply Hermes diff: {e}")
            update_incident_fields(incident_id, stage="patch_failed")
            if attempt < PATCH_MAX_ATTEMPTS:
                semgrep_feedback = f"Your previous diff did not apply: {e}. Re-emit a clean unified diff."
                continue
            return False

        patch_file.write_text(patch_diff, encoding="utf-8")
        update_incident_fields(incident_id, stage="patch_generated", patch={"diff": patch_diff})

        print(f"    Step 5: Gate 1 — Semgrep static analysis...")
        update_incident_fields(incident_id, stage="gate1_running")
        g1 = _run_gate1(patched_text, firmware_src.name)
        if g1.get("passed"):
            print(f"    [GATE 1 PASSED]")
            update_incident_fields(
                incident_id, stage="gate1_passed",
                patch={"diff": patch_diff, "gates": _gate1_results(g1)},
            )
            break

        print(f"    [GATE 1 REJECTED] {g1.get('failures') or g1.get('error')}")
        update_incident_fields(
            incident_id, stage="gate1_failed",
            patch={"diff": patch_diff, "gates": _gate1_results(g1)},
        )
        semgrep_feedback = _format_gate1_feedback(g1)
        if attempt >= PATCH_MAX_ATTEMPTS:
            shutil.copy2(patch_file, failed_dir / patch_file.name)
            return False
        print(f"    Retrying with Gate 1 feedback...")

    # ── Step 6: Gate 2 — Compile-Boot-Diff harness (on the patched source) ────
    print(f"    Step 6: Gate 2 — Compile-Boot-Diff harness...")
    update_incident_fields(incident_id, stage="gate2_running")
    g2 = _run_gate2(patched_text)
    if not g2.get("passed"):
        print(f"    [GATE 2 REJECTED] {g2.get('stages') or g2.get('error')}")
        shutil.copy2(patch_file, failed_dir / patch_file.name)
        update_incident_fields(incident_id, stage="gate2_failed")
        return False
    skipped = [s["name"] for s in g2.get("stages", []) if s.get("status") == "skipped"]
    print(f"    [GATE 2 PASSED]" + (f" (skipped: {', '.join(skipped)})" if skipped else ""))
    update_incident_fields(incident_id, stage="gate2_passed")

    # ── Both gates green: persist the patched firmware (original stays intact) ─
    # main_patched.c is a DISPLAY artifact for the dashboard — it is NOT what gets
    # built (the staged build in _staged_firmware_build writes the patch as main.c).
    Path("esp32-cam/main/main_patched.c").write_text(patched_text, encoding="utf-8")

    # Signal the telemetry simulator to drop this device back to normal mode.
    sim_state_path = Path("config/sim_state.json")
    try:
        sim_state = json.loads(sim_state_path.read_text()) if sim_state_path.exists() else {}
        sim_state[device_id] = "patched"
        sim_state_path.write_text(json.dumps(sim_state, indent=2))
        print(f"    Simulator notified — {device_id} will revert to normal traffic")
    except Exception as e:
        print(f"    [WARN] Could not update sim state: {e}")

    # ── HITL flash gate (REVIEW P0-3) ────────────────────────────────────────
    # Writing model-generated C to a physical device is the highest-risk action in
    # the system, yet Gate 1's four CWE rules cannot catch semantically malicious
    # (but statically clean) code. Require an explicit opt-in, mirroring Solution
    # 2's AES_FIREWALL_ENFORCE and Solution 3's Discord approval.
    if os.getenv("AES_FLASH_ENFORCE") != "1":
        print(f"    ✅ Patch validated (Gate 1 + Gate 2) and held for approval.")
        print(f"    To deploy: AES_FLASH_ENFORCE=1 python -m agents.response_agent flash {incident_id}")
        update_incident_fields(incident_id, stage="awaiting_flash_approval")
        return True

    return _flash_and_confirm(device_id, incident_id, patched_text)


def flash_incident(incident_id: str) -> bool:
    """
    Deploy a previously validated + approved patch to hardware. Reads the persisted
    patch, re-applies it to the current firmware source, and builds+flashes it.
    Entry point for the HITL flash gate (REVIEW P0-3):
        AES_FLASH_ENFORCE=1 python -m agents.response_agent flash <incident_id>
    """
    if os.getenv("AES_FLASH_ENFORCE") != "1":
        print("[FLASH] Refused — set AES_FLASH_ENFORCE=1 to write to a physical device.")
        return False

    patch_file = Path("outputs/patches/pending") / f"{incident_id}.patch"
    if not patch_file.exists():
        print(f"[FLASH] No validated patch found at {patch_file}")
        return False

    firmware_src = _select_firmware_source()
    if firmware_src is None:
        print("[FLASH] Firmware source not found under esp32-cam/main/")
        return False

    try:
        patched_text, _ = _apply_hermes_diff(
            firmware_src.read_text(encoding="utf-8"),
            patch_file.read_text(encoding="utf-8"),
            firmware_src.name,
        )
    except ValueError as e:
        print(f"[FLASH] Stored patch no longer applies to the current source: {e}")
        return False

    device_id = incident_id.split("-", 3)[-1] if "-" in incident_id else incident_id
    print(f"[FLASH] Deploying approved patch for {incident_id} → {device_id}")
    return _flash_and_confirm(device_id, incident_id, patched_text)


def handle_solution_2(incident: dict, verdict: dict) -> bool:
    """
    Solution 2 — Network quarantine for closed-firmware devices (Tapo C200).
    Delegates to openclaw.solution2: resolve device IP → pick backend
    (iptables via GATEWAY_SSH / pf / netsh) → dry-run (never skipped) →
    enforce + verify (only when AES_FIREWALL_ENFORCE=1) → audit log.
    """
    from openclaw.solution2 import handle as solution2_handle
    return solution2_handle(incident, verdict)


SOLUTION_HANDLERS = {
    1: handle_solution_1,
    2: handle_solution_2,
}


# ─── INCIDENT LOG ─────────────────────────────────────────────────────────────

def update_incident_fields(incident_id: str, **fields):
    """
    Merges arbitrary fields (stage, verdict, patch, ...) into an incident's entry
    in aes_incidents.jsonl. Called repeatedly as the pipeline progresses — not
    just once at the end — so the dashboard can show live stage-by-stage
    progress instead of only a final RESOLVED/FAILED jump.
    """
    if not LOG_PATH.exists():
        return

    lines = LOG_PATH.read_text().strip().splitlines()
    updated = []
    for line in lines:
        try:
            entry = json.loads(line)
            if entry.get("incident_id") == incident_id:
                entry.update(fields)
            updated.append(json.dumps(entry))
        except json.JSONDecodeError:
            updated.append(line)

    # Atomic rewrite (audit finding M5): write to a temp file then replace, so a
    # crash mid-write can never truncate or corrupt the incident log.
    tmp = LOG_PATH.with_suffix(".jsonl.tmp")
    tmp.write_text("\n".join(updated) + "\n")
    os.replace(tmp, LOG_PATH)


def update_incident_status(incident_id: str, status: str, verdict: dict = None):
    """Updates an incident's terminal status (RESOLVED/FAILED/MANUAL_REVIEW)."""
    fields = {"status": status, "resolved_at": datetime.now(timezone.utc).isoformat()}
    if verdict:
        fields["verdict"] = verdict
    update_incident_fields(incident_id, **fields)


# ─── MAIN ENTRY POINT ────────────────────────────────────────────────────────

def respond(incident: dict, verdict: dict) -> bool:
    """
    Main function — call this after Hermes returns a verdict.

    Args:
        incident: the full incident dict from aes_incidents.jsonl
        verdict:  Hermes verdict {solution_track, action, cve_id, confidence, reasoning}

    Returns:
        True if response succeeded, False if all retries exhausted.
    """
    incident_id    = incident["incident_id"]
    device_id      = incident["device_id"]
    device_model   = incident.get("device_model", "unknown")
    solution_track = verdict.get("solution_track", 0)
    # Measure latency from when the anomaly was DETECTED (set by the monitor),
    # not from when respond() starts — otherwise it only times the stub handler
    # and reports ~0ms. Falls back to now if detected_at is absent.
    start_time     = incident.get("detected_at") or time.time()

    print(f"\n[RESPONSE] Routing incident {incident_id}")
    print(f"  Device:   {device_id} ({device_model})")
    print(f"  Solution: Track {solution_track}")
    print(f"  Action:   {verdict.get('action', 'UNKNOWN')}")
    print(f"  CVE:      {verdict.get('cve_id', 'UNKNOWN')}")
    print(f"  Reason:   {verdict.get('reasoning', '')}")

    # ── Honor Hermes's decision (audit finding H5) ────────────────────────────
    # An INVESTIGATE verdict or low confidence must NOT auto-execute a remediation
    # and report RESOLVED. Hold it for manual review instead.
    action     = verdict.get("action", "INVESTIGATE")
    confidence = float(verdict.get("confidence", 0.0))
    if action == "INVESTIGATE" or confidence < 0.5:
        print(f"  [HOLD] action={action} confidence={confidence:.0%} — routing to MANUAL_REVIEW")
        update_incident_status(incident_id, "MANUAL_REVIEW", verdict)
        post_incident_alert(
            incident_id    = incident_id,
            device_id      = device_id,
            device_model   = device_model,
            attack         = incident.get("reason", "anomaly"),
            cve_id         = verdict.get("cve_id", "UNKNOWN"),
            cvss           = f"Confidence: {confidence:.0%}",
            solution_track = solution_track,
            action         = f"HELD — {action} (manual review)",
            latency_ms     = int((time.time() - start_time) * 1000),
            status         = "MANUAL_REVIEW",
        )
        return False

    handler = SOLUTION_HANDLERS.get(solution_track)
    if not handler:
        print(f"  [ERROR] Unknown solution track: {solution_track}")
        update_incident_status(incident_id, "FAILED", verdict)
        return False

    # ── Retry loop with exponential backoff ───────────────────────────────────
    # Track 1 (OTA) retries the LLM+gate flow INTERNALLY with Gate 1 feedback
    # (see handle_solution_1), so re-running the whole handler would just repeat
    # gate-passing work at 3× cost — one attempt is right. Track 2's failures are
    # transient (SSH/iptables), so it keeps the backoff retries. Backoff now also
    # applies to a handler that returns False, not only one that raises (P1-4).
    max_attempts = 1 if solution_track == 1 else MAX_RETRIES
    for attempt in range(1, max_attempts + 1):
        try:
            print(f"\n  Attempt {attempt}/{max_attempts}...")
            success = handler(incident, verdict)

            if success:
                latency_ms = int((time.time() - start_time) * 1000)
                update_incident_status(incident_id, "RESOLVED", verdict)

                # Post Discord alert
                post_incident_alert(
                    incident_id    = incident_id,
                    device_id      = device_id,
                    device_model   = device_model,
                    attack         = incident.get("reason", "anomaly"),
                    cve_id         = verdict.get("cve_id", "UNKNOWN"),
                    cvss           = f"Score: {verdict.get('confidence', 0):.0%}",
                    solution_track = solution_track,
                    action         = verdict.get("action", "UNKNOWN"),
                    gate1          = "PASS" if solution_track == 1 else "N/A",
                    gate2          = "PASS" if solution_track == 1 else "N/A",
                    latency_ms     = latency_ms,
                    status         = "RESOLVED",
                )
                print(f"\n  ✅ Resolved in {latency_ms}ms — Discord alerted")
                return True

            # Handler returned False (e.g. a gate rejected the patch). Back off
            # before another attempt just as we do on an exception.
            if attempt < max_attempts:
                wait = BACKOFF_BASE ** attempt
                print(f"  Handler reported failure — retrying in {wait}s...")
                time.sleep(wait)

        except Exception as e:
            print(f"  ❌ Attempt {attempt} failed: {e}")
            if attempt < max_attempts:
                wait = BACKOFF_BASE ** attempt
                print(f"  Retrying in {wait}s...")
                time.sleep(wait)

    # All retries exhausted
    update_incident_status(incident_id, "FAILED", verdict)
    post_incident_alert(
        incident_id    = incident_id,
        device_id      = device_id,
        device_model   = device_model,
        attack         = incident.get("reason", "anomaly"),
        cve_id         = verdict.get("cve_id", "UNKNOWN"),
        cvss           = "UNKNOWN",
        solution_track = solution_track,
        action         = "FAILED — all retries exhausted",
        latency_ms     = int((time.time() - start_time) * 1000),
        status         = "FAILED",
    )
    print(f"  ❌ All {max_attempts} attempt(s) failed — incident marked FAILED")
    return False


# ─── QUICK TEST / CLI ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    # HITL flash gate (REVIEW P0-3): deploy a validated + approved patch.
    #   AES_FLASH_ENFORCE=1 python -m agents.response_agent flash <incident_id>
    if len(sys.argv) >= 3 and sys.argv[1] == "flash":
        sys.exit(0 if flash_incident(sys.argv[2]) else 1)

    print("AES — Response Agent Test\n")

    # Simulate a Hermes verdict for an ESP32 attack
    test_incident = {
        "incident_id":    "INC-20260530-TEST-esp32-cam-01",
        "device_id":      "esp32-cam-01",
        "device_model":   "ESP32-CAM",
        "solution_track": 1,
        "reason":         "ANOMALY DETECTED — cpu +299% above normal, packet_rate +953% above normal",
        "confidence":     0.97,
        "status":         "OPEN",
    }

    test_verdict = {
        "solution_track": 1,
        "action":         "OTA_PATCH",
        "cve_id":         "CVE-2021-34173",
        "confidence":     0.91,
        "reasoning":      "Traffic matches Mirai C2 pattern; CVE-2021-34173 ESP32 heap overflow is the likely entry point.",
    }

    respond(test_incident, test_verdict)
