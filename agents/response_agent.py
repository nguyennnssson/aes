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
  Track 1 → handle_solution_1() → strict signed-firmware remediation preparation
  Track 2 → handle_solution_2() → verified gateway quarantine
  (Solution 3 — the Hermes learning loop — is NOT routed here. It is triggered
   directly from the monitor path via skills.hitl.propose_skill(); see
   agents/monitor_agent_mqtt.py.)

RED LINES (never skip these):
  - Never write a live iptables rule without --check dry-run passing first.
  - Never install firmware without strict Gate 1/Gate 2 evidence, signature
    verification, hardware attestation, and hash-bound approval.
  - Never discard a failed patch — log to outputs/patches/failed/.

RETRY LOGIC:
  MAX_RETRIES = 3, backoff = 2^attempt seconds (2s, 4s, 8s).
  After all retries fail, incident is marked FAILED and Discord is notified.
"""

import difflib
import hmac
import json
import math
import os
import re
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
from agents.monitor_agent import DEVICE_REGISTRY, initialize_incident_audit, update_incident_entry

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


def _validate_patch_policy(patch_diff: str) -> str | None:
    """Reject model patches that alter the firmware's security control plane.

    Gate 1 detects known unsafe C patterns; this complementary policy prevents a
    small vulnerability fix from quietly changing trust anchors, identity,
    credentials, OTA state, or boot attestation. Such changes require a normal
    reviewed source-code change, not autonomous incident remediation.
    """
    changed = [line[1:] for line in patch_diff.splitlines()
               if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]
    if len(changed) > 100:
        return f"patch changes {len(changed)} lines; autonomous limit is 100"
    sensitive = (
        "config_aes_", "mqtt_broker", "mqtt_cfg", "srv_cert", "certificate",
        "username", "password", "validate_and_confirm_app", "esp_ota_",
        "esp_efuse", "secure_boot", "flash_encrypt", "boot_id", "device_id",
        "firmware_version", "system(", "popen(",
    )
    for line in changed:
        lowered = line.lower()
        if line.lstrip().startswith("#include"):
            return "autonomous patches may not expand the include/dependency surface"
        hit = next((token for token in sensitive if token in lowered), None)
        if hit:
            return f"patch touches protected firmware control-plane token {hit!r}"
    return None


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
    ("esp32-cwe134-nonliteral-format",     "CWE-134", "format string"),
    ("esp32-cwe190-unchecked-allocation",  "CWE-690", "unchecked allocation"),
    ("esp32-private-key-material",          "KEY",     "private key material"),
]

OUTCOME_RESOLVED = "resolved"
OUTCOME_PENDING = "pending"
OUTCOME_FAILED = "failed"
_INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,159}$")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _incident_paths(incident_id: str) -> dict[str, Path]:
    if not isinstance(incident_id, str) or not _INCIDENT_ID_RE.fullmatch(incident_id):
        raise ValueError("incident_id contains unsafe characters")
    pending = Path("outputs/patches/pending")
    failed = Path("outputs/patches/failed")
    deployed = Path("outputs/patches/deployed")
    artifact = Path("outputs/gate2") / incident_id
    return {
        "pending": pending,
        "failed": failed,
        "deployed": deployed,
        "patch": pending / f"{incident_id}.patch",
        "manifest": pending / f"{incident_id}.manifest.json",
        "failed_patch": failed / f"{incident_id}.patch",
        "failed_manifest": failed / f"{incident_id}.manifest.json",
        "deployed_patch": deployed / f"{incident_id}.patch",
        "deployed_manifest": deployed / f"{incident_id}.manifest.json",
        "artifact": artifact,
    }


def _archive_failed_patch(paths: dict[str, Path], manifest: dict | None = None):
    """Move, rather than copy, a rejected patch out of the deployable queue."""
    paths["failed"].mkdir(parents=True, exist_ok=True)
    if manifest is not None:
        manifest = {**manifest, "validation_status": "REJECTED"}
        paths["manifest"].write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if paths["patch"].exists():
        os.replace(paths["patch"], paths["failed_patch"])
    if paths["manifest"].exists():
        os.replace(paths["manifest"], paths["failed_manifest"])


def _approval_signature(manifest: dict) -> str:
    key = os.getenv("AES_DEPLOY_APPROVAL_KEY", "")
    if len(key) < 32:
        raise ValueError("AES_DEPLOY_APPROVAL_KEY must contain at least 32 characters")
    bound = {
        "incident_id": manifest.get("incident_id"),
        "device_id": manifest.get("device_id"),
        "patch_sha256": manifest.get("patch_sha256"),
        "source_sha256": manifest.get("source_sha256"),
        "patched_source_sha256": manifest.get("patched_source_sha256"),
        "binary_sha256": manifest.get("binary_sha256"),
        "artifact_path": manifest.get("artifact_path"),
        "firmware_version": manifest.get("firmware_version"),
    }
    return hmac.new(key.encode("utf-8"), json.dumps(bound, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()


def _load_incident(incident_id: str) -> dict | None:
    if not LOG_PATH.exists():
        return None
    for line in LOG_PATH.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("incident_id") == incident_id:
            return entry
    return None


def _gate1_results(g1: dict) -> list:
    """Turn gate1.py's {"passed", "failures": [{"rule_id","line","message"}]} into
    the dashboard's GateResult[] — one row per known rule, real pass/fail + note."""
    by_rule = {f.get("rule_id"): f for f in (g1.get("failures") or [])}
    return [
        {
            "rule_id": short_id,
            "label":   label,
            "passed":  semgrep_id not in by_rule,
            "note":    by_rule[semgrep_id]["message"] if semgrep_id in by_rule else "pass",
        }
        for semgrep_id, short_id, label in _GATE1_RULES
    ]


# ─── SOLUTION HANDLERS ───────────────────────────────────────────────────────
# Handlers return resolved, pending, or failed (legacy True remains accepted).
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
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                cwd="gates/semgrep", timeout=120,
            )
        except subprocess.TimeoutExpired:
            return {"passed": False, "error": "Gate 1 timed out after 120s"}
        print(f"    [GATE 1 OUTPUT]\n{g1_proc.stdout}\n{g1_proc.stderr}".rstrip())
        try:
            marker = "--- GATE 1 OUTPUT RESULT ---"
            g1_text = g1_proc.stdout
            result = json.loads(g1_text[g1_text.index(marker) + len(marker):].strip())
            if g1_proc.returncode != 0:
                result["passed"] = False
                result.setdefault("error", f"Gate 1 exited with code {g1_proc.returncode}")
            return result
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


def _run_gate2(patched_text: str, incident_id: str) -> dict:
    """Run the Compile-Boot-Diff harness on the patched source. Returns its
    {"passed", "stages"|"error"} dict. Never raises."""
    gate2_path = Path("gates/gate2.py")
    g2_args = [sys.executable, str(gate2_path.resolve())]
    paths = _incident_paths(incident_id)
    env = os.environ.copy()
    env["GATE2_ARTIFACT_DIR"] = str(paths["artifact"])
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False, encoding="utf-8") as g2_src:
        g2_src.write(patched_text)
        g2_src_path = g2_src.name
    try:
        g2_proc = subprocess.run(
            g2_args + [g2_src_path], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=900, env=env,
        )
        marker = "--- GATE 2 OUTPUT RESULT ---"
        g2_text = g2_proc.stdout
        result = json.loads(g2_text[g2_text.index(marker) + len(marker):].strip())
        skipped = any(stage.get("status") == "skipped" for stage in result.get("stages", []))
        if g2_proc.returncode != 0 or skipped or not result.get("strict"):
            result["passed"] = False
            result.setdefault("error", "Gate 2 did not complete every strict stage")
        return result
    except subprocess.TimeoutExpired:
        return {"passed": False, "error": "Gate 2 timed out after 900s"}
    except (ValueError, json.JSONDecodeError):
        return {"passed": False, "error": "Gate 2 output parse failure"}
    finally:
        os.unlink(g2_src_path)


def _flash_and_confirm(device_id: str, incident_id: str, manifest: dict) -> bool:
    """
    Install the exact artifact certified by Gate 2 and confirm an authenticated
    fresh boot. Missing hardware or evidence is a failure, never a simulation.
    """
    firmware_bin = Path(manifest.get("artifact_path", ""))
    if (not firmware_bin.is_file()
            or _sha256_file(firmware_bin) != manifest.get("binary_sha256")):
        print("    [ERROR] Gate 2 artifact is missing or changed")
        update_incident_fields(incident_id, stage="artifact_invalid")
        return False

    public_key = os.getenv("AES_FIRMWARE_PUBLIC_KEY")
    espsecure = shutil.which("espsecure.py") or shutil.which("espsecure")
    esptool = shutil.which("esptool.py") or shutil.which("esptool")
    if not public_key or not Path(public_key).is_file() or not espsecure:
        print("    [ERROR] ESP-IDF signature verification or the firmware public key is not configured")
        update_incident_fields(incident_id, stage="signature_unverified")
        return False
    if not esptool:
        print("    [ERROR] ESP-IDF flashing tool is not available")
        update_incident_fields(incident_id, stage="flash_failed")
        return False
    verify = subprocess.run(
        [espsecure, "verify_signature", "--version", "2", "--keyfile", public_key, str(firmware_bin)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
    )
    if verify.returncode != 0:
        print(f"    [ERROR] Firmware signature rejected: {(verify.stderr or verify.stdout)[-400:]}")
        update_incident_fields(incident_id, stage="signature_unverified")
        return False
    if os.getenv("AES_HARDWARE_SECURITY_VERIFIED") != "1":
        print("    [ERROR] Refused: secure boot + flash encryption have not been attested for this device")
        update_incident_fields(incident_id, stage="hardware_security_unverified")
        return False

    device_info = DEVICE_REGISTRY.get(device_id, {})
    serial_port = device_info.get("port") or os.getenv("ESP32_PORT")
    if not serial_port:
        print(f"    [ERROR] No serial port for {device_id}. Set ESP32_PORT or add 'port' "
              f"to config/device_registry.json.")
        update_incident_fields(incident_id, stage="flash_failed")
        return False

    print(f"    Installing signed {firmware_bin.name} → {serial_port}...")
    update_incident_fields(incident_id, stage="flashing")
    try:
        flash = subprocess.run(
            [esptool, "--chip", "esp32", "--port", serial_port,
             "--baud", "460800", "write_flash", "0x10000", str(firmware_bin)],
            capture_output=True, text=True, timeout=120,
        )
        if flash.returncode != 0:
            print(f"    [ERROR] Flash failed:\n{flash.stderr[-500:]}")
            update_incident_fields(incident_id, stage="flash_failed")
            return False
        print(f"    Flash complete")
    except FileNotFoundError:
        print("    [ERROR] ESP-IDF flashing tool disappeared before deployment")
        update_incident_fields(incident_id, stage="flash_failed")
        return False
    except subprocess.TimeoutExpired:
        print(f"    [ERROR] Flash timed out after 120s")
        update_incident_fields(incident_id, stage="flash_failed")
        return False

    # ── MQTT boot confirmation (35s window per OTA_LIFECYCLE.md) ──────────────
    # Boot evidence must come from THIS device's ACL-restricted MQTT identity and
    # report the approved firmware version, a new boot id, and a post-flash
    # timestamp. These are corroborating checks; the hardware/build gates remain
    # the primary authorization boundary.
    print(f"    Waiting for {device_id} MQTT boot confirmation (35s)...")
    update_incident_fields(incident_id, stage="validating")
    from agents.mqtt_compat import configure_mqtt_client, make_mqtt_client

    flashed_at = datetime.now(timezone.utc).isoformat()
    confirmed = threading.Event()
    boot_evidence = {}

    def _on_boot_msg(client, _userdata, msg):
        if len(msg.payload) > 4096:
            return
        try:
            data = json.loads(
                msg.payload.decode("utf-8"),
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
            )
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return
        if data.get("device_id") != device_id:
            return
        # Authenticated per-device broker ACLs make this topic an identity proof.
        # The firmware must also provide a fresh boot id and timestamp.
        ts = data.get("timestamp")
        boot_id = data.get("boot_id")
        try:
            boot_time = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            flash_time = datetime.fromisoformat(flashed_at)
        except ValueError:
            return
        if boot_time.tzinfo is None or boot_time.astimezone(timezone.utc) < flash_time:
            return
        if not isinstance(boot_id, str) or len(boot_id) < 8:
            return
        if data.get("firmware_version") != manifest.get("firmware_version"):
            return
        if type(data.get("sequence")) is not int or not (0 <= data["sequence"] <= 10):
            return
        boot_evidence.update({"boot_id": boot_id, "timestamp": ts})
        confirmed.set()
        client.disconnect()

    boot_mqtt = make_mqtt_client("aes-boot-verify")
    configure_mqtt_client(boot_mqtt, role="monitor")
    boot_mqtt.on_message = _on_boot_msg
    try:
        mqtt_host = os.getenv("MQTT_HOST", "localhost")
        mqtt_port = int(os.getenv("MQTT_PORT", "8883"))
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
        update_incident_fields(incident_id, stage="boot_confirmed", boot_evidence=boot_evidence)
        return True
    print(f"    ❌ Boot confirmation timeout — device may have auto-rolled back")
    update_incident_fields(incident_id, stage="boot_timeout")
    return False


# How many times to ask Hermes for a fix, feeding Gate 1 findings back each retry.
PATCH_MAX_ATTEMPTS = 3


def handle_solution_1(incident: dict, verdict: dict) -> str:
    """
    Solution 1 — signed firmware remediation for open-firmware ESP32 devices.
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

    print(f"  [SOLUTION 1] Signed firmware remediation pipeline on {device_id}")
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

    paths = _incident_paths(incident_id)
    paths["pending"].mkdir(parents=True, exist_ok=True)
    paths["failed"].mkdir(parents=True, exist_ok=True)
    patch_file = paths["patch"]
    manifest = None

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

        policy_error = _validate_patch_policy(patch_diff)
        if policy_error:
            print(f"    [PATCH POLICY REJECTED] {policy_error}")
            update_incident_fields(incident_id, stage="patch_policy_failed")
            semgrep_feedback = f"Patch policy rejected your diff: {policy_error}. Keep the fix local to the vulnerable data operation."
            if attempt < PATCH_MAX_ATTEMPTS:
                continue
            _archive_failed_patch(paths, manifest)
            return OUTCOME_FAILED

        patch_file.write_text(patch_diff, encoding="utf-8")
        manifest = {
            "schema_version": 1,
            "incident_id": incident_id,
            "device_id": device_id,
            "source_path": str(firmware_src),
            "source_sha256": _sha256_text(vulnerable_code),
            "patched_source_sha256": _sha256_text(patched_text),
            "patch_sha256": _sha256_file(patch_file),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "validation_status": "VALIDATING",
        }
        paths["manifest"].write_text(json.dumps(manifest, indent=2), encoding="utf-8")
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
            _archive_failed_patch(paths, manifest)
            return OUTCOME_FAILED
        print(f"    Retrying with Gate 1 feedback...")

    # ── Step 6: Gate 2 — Compile-Boot-Diff harness (on the patched source) ────
    print(f"    Step 6: Gate 2 — Compile-Boot-Diff harness...")
    update_incident_fields(incident_id, stage="gate2_running")
    g2 = _run_gate2(patched_text, incident_id)
    if not g2.get("passed"):
        print(f"    [GATE 2 REJECTED] {g2.get('stages') or g2.get('error')}")
        if manifest is not None:
            manifest["gate1"] = g1
            manifest["gate2"] = g2
        _archive_failed_patch(paths, manifest)
        update_incident_fields(incident_id, stage="gate2_failed")
        return OUTCOME_FAILED
    skipped = [s["name"] for s in g2.get("stages", []) if s.get("status") == "skipped"]
    print(f"    [GATE 2 PASSED]" + (f" (skipped: {', '.join(skipped)})" if skipped else ""))
    compile_stage = next((s for s in g2.get("stages", []) if s.get("name") == "compile"), {})
    artifact_path = Path(compile_stage.get("artifact_path", ""))
    if (not artifact_path.is_file()
            or compile_stage.get("source_sha256") != _sha256_text(patched_text)
            or compile_stage.get("binary_sha256") != _sha256_file(artifact_path)
            or not isinstance(compile_stage.get("firmware_version"), str)
            or not compile_stage.get("firmware_version")):
        print("    [GATE 2 REJECTED] Artifact evidence does not match the patched source")
        _archive_failed_patch(paths, manifest)
        update_incident_fields(incident_id, stage="gate2_failed")
        return OUTCOME_FAILED

    manifest.update({
        "gate1": g1,
        "gate2": g2,
        "artifact_path": str(artifact_path.resolve()),
        "binary_sha256": compile_stage["binary_sha256"],
        "firmware_version": compile_stage["firmware_version"],
        "validation_status": "VALIDATED",
        "validated_at": datetime.now(timezone.utc).isoformat(),
    })
    paths["manifest"].write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    update_incident_fields(
        incident_id, stage="awaiting_flash_approval", deployment_manifest={
            key: manifest[key] for key in (
                "patch_sha256", "source_sha256", "patched_source_sha256",
                "binary_sha256", "artifact_path", "firmware_version", "validation_status",
            )
        },
    )
    print("    Patch validated and held. Approval must be bound to this exact artifact.")
    print(f"    Approve: python -m agents.response_agent approve {incident_id} <approver>")
    return OUTCOME_PENDING


def approve_flash_incident(incident_id: str, approver: str) -> bool:
    """Bind a human approval to the exact patch, source, and firmware hashes."""
    audit_problems = initialize_incident_audit(production=os.getenv("AES_PRODUCTION") == "1")
    if audit_problems:
        print("[APPROVE] Refused — incident audit verification failed: " + "; ".join(audit_problems[:3]))
        return False
    try:
        paths = _incident_paths(incident_id)
    except ValueError as exc:
        print(f"[APPROVE] Refused: {exc}")
        return False
    if not approver or len(approver) > 128 or any(ord(char) < 32 for char in approver):
        print("[APPROVE] Refused: approver must be a printable identity (1-128 chars)")
        return False
    try:
        manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"[APPROVE] No valid deployment manifest for {incident_id}")
        return False
    incident = _load_incident(incident_id)
    if (not incident or manifest.get("validation_status") != "VALIDATED"
            or incident.get("device_id") != manifest.get("device_id")
            or not isinstance(manifest.get("firmware_version"), str)
            or not manifest.get("firmware_version")
            or incident.get("status") not in {"OPEN", "AWAITING_APPROVAL"}
            or incident.get("stage") != "awaiting_flash_approval"):
        print("[APPROVE] Incident/manifest state is not eligible for approval")
        return False
    try:
        signature = _approval_signature(manifest)
    except ValueError as exc:
        print(f"[APPROVE] Refused: {exc}")
        return False
    manifest["approval"] = {
        "approver": approver,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "signature": signature,
        "algorithm": "hmac-sha256",
    }
    manifest["validation_status"] = "APPROVED"
    tmp = paths["manifest"].with_suffix(".manifest.json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    os.replace(tmp, paths["manifest"])
    update_incident_fields(incident_id, stage="approved_for_install", status="APPROVED")
    print(f"[APPROVE] {incident_id} approved by {approver}; hashes are now bound")
    return True


def flash_incident(incident_id: str) -> bool:
    """Install only a signed artifact carrying a valid hash-bound approval."""
    if os.getenv("AES_FLASH_ENFORCE") != "1":
        print("[FLASH] Refused — set AES_FLASH_ENFORCE=1 to write to a physical device.")
        return False
    audit_problems = initialize_incident_audit(production=os.getenv("AES_PRODUCTION") == "1")
    if audit_problems:
        print("[FLASH] Refused — incident audit verification failed: " + "; ".join(audit_problems[:3]))
        return False

    try:
        paths = _incident_paths(incident_id)
        manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[FLASH] No valid approved manifest: {exc}")
        return False
    incident = _load_incident(incident_id)
    if (not incident or incident.get("device_id") != manifest.get("device_id")
            or incident.get("status") != "APPROVED"
            or incident.get("stage") != "approved_for_install"):
        print("[FLASH] Incident identity does not match the manifest")
        return False
    approval = manifest.get("approval") or {}
    if manifest.get("validation_status") != "APPROVED":
        print("[FLASH] Manifest has not been approved")
        return False
    if not isinstance(manifest.get("firmware_version"), str) or not manifest.get("firmware_version"):
        print("[FLASH] Manifest does not bind an expected firmware version")
        return False
    try:
        expected_approval = _approval_signature(manifest)
    except ValueError as exc:
        print(f"[FLASH] Refused: {exc}")
        return False
    if not hmac.compare_digest(str(approval.get("signature", "")), expected_approval):
        print("[FLASH] Approval signature does not match this artifact")
        return False
    if not paths["patch"].is_file() or _sha256_file(paths["patch"]) != manifest.get("patch_sha256"):
        print("[FLASH] Patch changed after validation")
        return False
    expected_artifact = paths["artifact"].resolve()
    try:
        manifest_artifact = Path(str(manifest.get("artifact_path", ""))).resolve(strict=True)
    except (OSError, RuntimeError):
        print("[FLASH] Validated artifact is missing")
        return False
    if manifest_artifact != expected_artifact:
        print("[FLASH] Artifact path is not scoped to this incident")
        return False
    firmware_src = _select_firmware_source()
    if firmware_src is None or _sha256_text(firmware_src.read_text(encoding="utf-8")) != manifest.get("source_sha256"):
        print("[FLASH] Source changed after validation; regenerate and reapprove the patch")
        return False

    device_id = manifest["device_id"]
    print(f"[FLASH] Deploying approved patch for {incident_id} → {device_id}")
    if not _flash_and_confirm(device_id, incident_id, manifest):
        return False

    manifest["validation_status"] = "DEPLOYED"
    manifest["deployed_at"] = datetime.now(timezone.utc).isoformat()
    paths["manifest"].write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    paths["deployed"].mkdir(parents=True, exist_ok=True)
    os.replace(paths["patch"], paths["deployed_patch"])
    os.replace(paths["manifest"], paths["deployed_manifest"])
    update_incident_status(incident_id, "RESOLVED", incident.get("verdict"))
    return True


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
    update_incident_entry(incident_id, fields)


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
    trusted_track = incident.get("solution_track") or (DEVICE_REGISTRY.get(device_id) or {}).get("solution_track", 0)
    solution_track = int(trusted_track or 0)
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
    action = verdict.get("action", "INVESTIGATE")
    try:
        confidence = float(verdict.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    if not math.isfinite(confidence):
        confidence = 0.0
    expected_action = {1: "PATCH_OTA", 2: "BLOCK_FIREWALL", 3: "REWRITE_SKILL"}.get(solution_track)
    if verdict.get("solution_track") != solution_track or action != expected_action:
        print(f"  [HOLD] verdict action/track mismatch: trusted track {solution_track} requires {expected_action}")
        action = "INVESTIGATE"
        confidence = 0.0
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
    # Track 1 firmware remediation retries the LLM+gate flow INTERNALLY with Gate 1 feedback
    # (see handle_solution_1), so re-running the whole handler would just repeat
    # gate-passing work at 3× cost — one attempt is right. Track 2's failures are
    # transient (SSH/iptables), so it keeps the backoff retries. Backoff now also
    # applies to a handler that returns False, not only one that raises (P1-4).
    max_attempts = 1 if solution_track == 1 else MAX_RETRIES
    for attempt in range(1, max_attempts + 1):
        try:
            print(f"\n  Attempt {attempt}/{max_attempts}...")
            outcome = handler(incident, verdict)

            if outcome is True or outcome == OUTCOME_RESOLVED:
                latency_ms = int((time.time() - start_time) * 1000)
                update_incident_status(incident_id, "RESOLVED", verdict)

                # Post Discord alert
                post_incident_alert(
                    incident_id    = incident_id,
                    device_id      = device_id,
                    device_model   = device_model,
                    attack         = incident.get("reason", "anomaly"),
                    cve_id         = verdict.get("cve_id", "UNKNOWN"),
                    cvss           = f"Score: {confidence:.0%}",
                    solution_track = solution_track,
                    action         = verdict.get("action", "UNKNOWN"),
                    gate1          = "PASS" if solution_track == 1 else "N/A",
                    gate2          = "PASS" if solution_track == 1 else "N/A",
                    latency_ms     = latency_ms,
                    status         = "RESOLVED",
                )
                print(f"\n  ✅ Resolved in {latency_ms}ms — Discord alerted")
                return True

            if outcome == OUTCOME_PENDING:
                latency_ms = int((time.time() - start_time) * 1000)
                update_incident_fields(
                    incident_id, status="AWAITING_APPROVAL",
                    updated_at=datetime.now(timezone.utc).isoformat(), verdict=verdict,
                )
                post_incident_alert(
                    incident_id=incident_id, device_id=device_id,
                    device_model=device_model, attack=incident.get("reason", "anomaly"),
                    cve_id=verdict.get("cve_id", "UNKNOWN"),
                    cvss=f"Confidence: {confidence:.0%}", solution_track=solution_track,
                    action=f"HELD — {action} awaiting explicit enforcement approval",
                    latency_ms=latency_ms, status="AWAITING_APPROVAL",
                )
                print("  ⏸ Validated but not enforced — incident remains open for approval")
                return False

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
    # Hash-bound human approval:
    #   AES_DEPLOY_APPROVAL_KEY=... python -m agents.response_agent approve <incident_id> <approver>
    if len(sys.argv) >= 4 and sys.argv[1] == "approve":
        sys.exit(0 if approve_flash_incident(sys.argv[2], sys.argv[3]) else 1)

    # HITL flash gate (REVIEW P0-3): deploy a validated + approved patch.
    #   AES_FLASH_ENFORCE=1 AES_DEPLOY_APPROVAL_KEY=... \
    #       python -m agents.response_agent flash <incident_id>
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
        "action":         "PATCH_OTA",
        "cve_id":         "CVE-2021-34173",
        "confidence":     0.91,
        "reasoning":      "Traffic matches Mirai C2 pattern; CVE-2021-34173 ESP32 heap overflow is the likely entry point.",
    }

    respond(test_incident, test_verdict)
