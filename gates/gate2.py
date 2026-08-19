"""
AES — Gate 2: Compile-Boot-Diff Harness
========================================
Owner: Vy Tuong Khong (Firmware)

The DYNAMIC pre-deploy check. Gate 1 (Semgrep) proves the patch introduces no
new static vulnerability; Gate 2 proves the patched firmware actually WORKS:
it compiles, it boots on a reference device, and the original attack no longer
trips the anomaly detector.

STAGES (each reports pass / fail / skipped):
  1. structure — the patched source is well-formed: non-trivial, balanced
     braces/parens, no leftover diff/merge markers, app_main() present.
     Always runs. A failure here means the diff application mangled the file.
  2. compile — stage the patched source into a copy of the ESP-IDF project and
     run `idf.py build`. Skipped when the ESP-IDF toolchain isn't on PATH.
  3. boot-diff — flash the build to a REFERENCE ESP32 (never the production
     device), wait for its MQTT telemetry handshake (boot proof), then replay
     the recorded attack traffic and confirm the anomaly no longer fires.
     Skipped unless GATE2_REFERENCE_PORT is set (reference hardware attached).

VERDICT:
  Strict is the default: every stage must run and pass. `--allow-skips` exists
  only for local diagnostics and its result is never deployable.

OUTPUT CONTRACT (same shape response_agent.py parses for Gate 1):
  human-readable log, then a marker line and JSON:
    --- GATE 2 OUTPUT RESULT ---
    {"passed": true, "stages": [{"name", "status", "detail"}, ...]}

USAGE:
  python gate2.py <patched_source.c> [--allow-skips]

ENV:
  GATE2_REFERENCE_PORT — serial port of the reference ESP32 (e.g. COM7,
                         /dev/ttyUSB1). Unset = boot-diff stage skipped.
  GATE2_ATTACK_REPLAY  — path to a JSONL of recorded attack telemetry to
                         replay after boot (default: aes_incidents.jsonl
                         deviations replayed through the live detection params).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import hashlib
import time
from pathlib import Path

# Windows consoles default to cp1252, which can't encode the status glyphs.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

_REPO_ROOT    = Path(__file__).resolve().parents[1]
_PROJECT_DIR  = _REPO_ROOT / "esp32-cam"
_INCIDENTS    = _REPO_ROOT / "aes_incidents.jsonl"

PASS, FAIL, SKIPPED = "pass", "fail", "skipped"


def _stage(name: str, status: str, detail: str, **evidence) -> dict:
    icon = {"pass": "✅", "fail": "❌", "skipped": "⏭"}[status]
    print(f"[GATE 2] {icon} {name}: {detail}")
    return {"name": name, "status": status, "detail": detail, **evidence}


# ─── STAGE 1: STRUCTURE ──────────────────────────────────────────────────────

def check_structure(src_path: Path) -> dict:
    """Static sanity of the patched file — catches mangled diff application."""
    if not src_path.exists():
        return _stage("structure", FAIL, f"{src_path} does not exist")
    text = src_path.read_text(encoding="utf-8", errors="replace")

    if len(text) < 500:
        return _stage("structure", FAIL, f"suspiciously small ({len(text)} chars) — truncated by diff?")

    for marker in ("<<<<<<<", ">>>>>>>", "=======\n<<<<<<<"):
        if marker in text:
            return _stage("structure", FAIL, f"merge-conflict marker '{marker}' left in source")
    if re.search(r"^@@ ", text, re.MULTILINE):
        return _stage("structure", FAIL, "raw diff hunk header '@@' left in source")

    # Brace/paren balance on string- and comment-stripped text. Strings must be
    # removed first so URL literals such as "mqtts://..." are not mistaken for
    # comments and allowed to hide the remainder of the function.
    stripped = re.sub(r'"(\\.|[^"\\])*"|\'(\\.|[^\'\\])*\'', '""', text)
    stripped = re.sub(r'//[^\n]*|/\*.*?\*/', '', stripped, flags=re.DOTALL)
    for open_c, close_c in (("{", "}"), ("(", ")")):
        if stripped.count(open_c) != stripped.count(close_c):
            return _stage("structure", FAIL,
                          f"unbalanced {open_c}{close_c}: {stripped.count(open_c)} vs {stripped.count(close_c)}")

    if "app_main" not in text:
        return _stage("structure", FAIL, "app_main() missing — not a flashable ESP-IDF app")

    return _stage("structure", PASS, "well-formed C source, no diff artifacts, app_main present")


# ─── STAGE 2: COMPILE ────────────────────────────────────────────────────────

def check_compile(src_path: Path) -> dict:
    """Stage the patched source into a copy of the project and idf.py build it."""
    idf = shutil.which("idf.py")
    if not idf:
        return _stage("compile", SKIPPED, "idf.py not on PATH — ESP-IDF toolchain unavailable")

    with tempfile.TemporaryDirectory(prefix="aes-gate2-") as tmp:
        staged = Path(tmp) / "esp32-cam"
        shutil.copytree(
            _PROJECT_DIR, staged,
            ignore=shutil.ignore_patterns("build", "sdkconfig.old", "managed_components"),
        )
        # The staged build compiles ONLY the patched source as main.c — the
        # production tree is never touched by this gate.
        (staged / "main" / "main.c").write_text(
            src_path.read_text(encoding="utf-8"), encoding="utf-8")
        for extra in ("main_vulnerable.c", "main_patched.c"):
            (staged / "main" / extra).unlink(missing_ok=True)

        try:
            build = subprocess.run(
                [idf, "build"],
                capture_output=True, text=True, cwd=staged, timeout=600,
            )
        except subprocess.TimeoutExpired:
            return _stage("compile", FAIL, "idf.py build timed out after 600s")

        if build.returncode != 0:
            tail = (build.stderr or build.stdout)[-400:].replace("\n", " | ")
            return _stage("compile", FAIL, f"build failed: {tail}")

        build_dir = staged / "build"
        named = build_dir / "aes_esp32_cam.bin"
        bins = list(build_dir.glob("*.bin"))
        if named.exists():
            app_bin = named
        elif bins:
            app_bin = max(bins, key=lambda path: path.stat().st_size)
        else:
            return _stage("compile", FAIL, "build reported success but produced no .bin")

        # Keep the artifact in an incident-specific directory. A global
        # verified_firmware.bin allowed a later incident to reuse an unrelated
        # build. The source and binary hashes travel with the gate evidence.
        configured = os.getenv("GATE2_ARTIFACT_DIR", "outputs/gate2/diagnostic")
        out_dir = Path(configured)
        if not out_dir.is_absolute():
            out_dir = _REPO_ROOT / out_dir
        out_dir = out_dir.resolve()
        gate_root = (_REPO_ROOT / "outputs" / "gate2").resolve()
        if not out_dir.is_relative_to(gate_root):
            return _stage("compile", FAIL, "artifact directory must stay under outputs/gate2")
        out_dir.mkdir(parents=True, exist_ok=True)
        verified = out_dir / "firmware.bin"
        shutil.copy2(app_bin, verified)
        source_hash = hashlib.sha256(src_path.read_bytes()).hexdigest()
        binary_hash = hashlib.sha256(verified.read_bytes()).hexdigest()
        try:
            sdkconfig = (staged / "sdkconfig").read_text(encoding="utf-8")
            version_match = re.search(r'^CONFIG_AES_FIRMWARE_VERSION="([^"\r\n]{1,64})"$', sdkconfig, re.MULTILINE)
            firmware_version = version_match.group(1) if version_match else ""
        except OSError:
            firmware_version = ""
        if not firmware_version:
            verified.unlink(missing_ok=True)
            return _stage("compile", FAIL, "compiled configuration did not contain a firmware version")
        return _stage(
            "compile", PASS, f"clean build → {verified}",
            artifact_path=str(verified), source_sha256=source_hash,
            binary_sha256=binary_hash, firmware_version=firmware_version,
        )


# ─── STAGE 3: BOOT-DIFF ──────────────────────────────────────────────────────

def check_boot_diff(compile_result: dict) -> dict:
    """
    Flash the verified build to the REFERENCE device, confirm it boots (MQTT
    telemetry within 35s), then replay the recorded attack and confirm the
    anomaly no longer fires. Requires reference hardware — skipped otherwise.
    """
    port = os.getenv("GATE2_REFERENCE_PORT")
    if not port:
        return _stage("boot-diff", SKIPPED,
                      "GATE2_REFERENCE_PORT not set — no reference ESP32 attached")
    if compile_result["status"] != PASS:
        return _stage("boot-diff", SKIPPED, "no verified build to flash (compile stage did not pass)")

    firmware_path = compile_result.get("artifact_path")
    if not firmware_path:
        return _stage("boot-diff", FAIL, "compile evidence did not identify an artifact")
    firmware = Path(firmware_path)
    if not firmware.exists() or hashlib.sha256(firmware.read_bytes()).hexdigest() != compile_result.get("binary_sha256"):
        return _stage("boot-diff", FAIL, "compiled artifact is missing or its hash changed")
    esptool = shutil.which("esptool.py") or shutil.which("esptool")
    if not esptool:
        return _stage("boot-diff", SKIPPED, "esptool not installed (pip install esptool)")

    print(f"[GATE 2] Flashing reference device on {port}...")
    try:
        flash = subprocess.run(
            [esptool, "--chip", "esp32", "--port", port, "--baud", "460800",
             "write_flash", "0x10000", str(firmware)],
            capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return _stage("boot-diff", FAIL, "reference flash timed out")
    if flash.returncode != 0:
        return _stage("boot-diff", FAIL, f"reference flash failed: {flash.stderr[-300:]}")

    # Boot proof: the reference device must publish telemetry within 35s
    # (mirrors the on-device 30s validate-or-rollback window in main.c).
    sys.path.insert(0, str(_REPO_ROOT))
    from agents.mqtt_compat import configure_mqtt_client, make_mqtt_client
    from agents.monitor_agent import MonitorAgent, Telemetry, evaluate_detection, load_active_params
    import threading

    ref_device = os.getenv("GATE2_REFERENCE_DEVICE")
    if not ref_device:
        return _stage("boot-diff", FAIL, "GATE2_REFERENCE_DEVICE is required; wildcard boot proof is forbidden")
    attack_harness = os.getenv("GATE2_ATTACK_HARNESS")
    if not attack_harness:
        return _stage("boot-diff", FAIL, "GATE2_ATTACK_HARNESS is required for an active hardware test")
    harness_path = Path(attack_harness).resolve()
    if not harness_path.is_file():
        return _stage("boot-diff", FAIL, f"attack harness not found: {harness_path}")

    booted   = threading.Event()
    readings = []
    boot_id = None

    def _on_msg(client, _u, msg):
        try:
            data = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if data.get("device_id") != ref_device:
            return
        current_boot = data.get("boot_id")
        if not isinstance(current_boot, str) or len(current_boot) < 8:
            return
        if data.get("firmware_version") != compile_result.get("firmware_version"):
            return
        if type(data.get("sequence")) is not int or not (0 <= data["sequence"] <= 1_000_000):
            return
        try:
            telemetry = Telemetry(
                device_id=data["device_id"], timestamp=data["timestamp"],
                cpu_percent=float(data["cpu_percent"]),
                memory_percent=float(data["memory_percent"]),
                packet_rate=float(data["packet_rate"]),
                connection_count=int(data["connection_count"]),
            )
            if telemetry.validate():
                return
        except (KeyError, TypeError, ValueError, OverflowError):
            return
        readings.append(data)
        booted.set()

    client = make_mqtt_client("aes-gate2-harness")
    configure_mqtt_client(client, role="monitor")
    client.on_message = _on_msg
    try:
        client.connect(os.getenv("MQTT_HOST", "localhost"),
                       int(os.getenv("MQTT_PORT", "8883")), keepalive=10)
        client.subscribe(f"aes/telemetry/{ref_device}", qos=1)
        client.loop_start()
        boot_ok = booted.wait(timeout=35)
    except Exception as e:
        return _stage("boot-diff", FAIL, f"MQTT boot verification error: {e}")

    if not boot_ok:
        try:
            client.loop_stop(); client.disconnect()
        except Exception:
            pass
        return _stage("boot-diff", FAIL,
                      "no telemetry within 35s — device likely rolled back the patch")

    boot_id = readings[-1]["boot_id"]
    before_attack = len(readings)
    try:
        harness_command = ([sys.executable, str(harness_path)] if harness_path.suffix.lower() == ".py"
                           else [str(harness_path)])
        harness = subprocess.run(
            harness_command + ["--device", ref_device, "--port", port],
            capture_output=True, text=True, timeout=120,
        )
        if harness.returncode != 0:
            return _stage("boot-diff", FAIL, f"attack harness failed: {(harness.stderr or harness.stdout)[-300:]}")
        deadline = time.monotonic() + 20
        minimum = max(3, int(os.getenv("GATE2_MIN_ATTACK_READINGS", "3")))
        while time.monotonic() < deadline and len(readings) - before_attack < minimum:
            time.sleep(0.2)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return _stage("boot-diff", FAIL, f"attack harness could not run: {exc}")
    finally:
        try:
            client.loop_stop(); client.disconnect()
        except Exception:
            pass

    attack_readings = readings[before_attack:]
    if len(attack_readings) < minimum:
        return _stage("boot-diff", FAIL, f"only {len(attack_readings)} authenticated readings arrived during active replay")
    if any(reading.get("boot_id") != boot_id for reading in attack_readings):
        return _stage("boot-diff", FAIL, "reference device rebooted during the active attack test")

    # Attack replay: run the logged attack deviations back through the LIVE
    # detection params. The patch is proven when the reference device, running
    # patched firmware, no longer produces the attack signature — the recorded
    # signature must still be recognisable (detector sane) while the fresh
    # reference readings stay clean.
    replay_path = Path(os.getenv("GATE2_ATTACK_REPLAY", _INCIDENTS))
    from skills.trusted_labels import verify_ground_truth

    attacks = []
    if replay_path.exists():
        for line in replay_path.read_text().splitlines():
            try:
                candidate = json.loads(line)
                if verify_ground_truth(candidate, "ATTACK"):
                    attacks.append(candidate)
            except json.JSONDecodeError:
                pass
    if not attacks:
        return _stage("boot-diff", FAIL, f"no authenticated attack traffic to replay ({replay_path})")

    params = load_active_params()
    still_detected = sum(
        1 for a in attacks if evaluate_detection(a.get("deviations", {}), params)[0]
    )
    if still_detected / len(attacks) < 0.80:
        return _stage(
            "boot-diff", FAIL,
            f"detector regression recognized only {still_detected}/{len(attacks)} historical attacks",
        )

    # Fresh boot readings from the PATCHED firmware must look clean: compute
    # their real deviations against the stored per-device EWMA baseline and run
    # them through the same live detection rule.
    baseline_path = _REPO_ROOT / "config" / "ewma_baseline.json"
    try:
        baselines = json.loads(baseline_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        baselines = {}

    def _deviations(reading: dict) -> dict:
        base = baselines.get(reading.get("device_id", ""), {})
        out = {}
        for metric, key in (("cpu", "cpu_percent"), ("memory", "memory_percent"),
                            ("packet_rate", "packet_rate"), ("connections", "connection_count")):
            floor = MonitorAgent.MIN_BASELINE[metric]
            b = max(float(base.get(metric, 0.0)), floor)
            cur = float(reading.get(key, 0.0))
            out[metric] = max(0.0, (cur - b) / b)
        return out

    fresh_flagged = sum(
        1 for r in attack_readings if evaluate_detection(_deviations(r), params)[0]
    )

    if fresh_flagged:
        return _stage("boot-diff", FAIL, "authenticated reference telemetry became anomalous during active attack replay")
    return _stage(
        "boot-diff", PASS,
        f"authenticated boot {boot_id} survived active replay; {len(attack_readings)} readings remained clean; "
        f"detector regression recognized {still_detected}/{len(attacks)} historical attacks",
        boot_id=boot_id, attack_readings=len(attack_readings),
        historical_detected=still_detected, historical_total=len(attacks),
    )


# ─── MAIN ────────────────────────────────────────────────────────────────────

def run_gate2(src: Path, strict: bool = True) -> dict:
    print(f"[GATE 2] Compile-Boot-Diff harness on: {src}")
    stages = [check_structure(src)]
    if stages[0]["status"] == PASS:
        stages.append(check_compile(src))
        stages.append(check_boot_diff(stages[1]))
    else:
        stages.append(_stage("compile",   SKIPPED, "structure stage failed"))
        stages.append(_stage("boot-diff", SKIPPED, "structure stage failed"))

    any_fail    = any(s["status"] == FAIL for s in stages)
    any_skipped = any(s["status"] == SKIPPED for s in stages)
    passed = not any_fail and not (strict and any_skipped)

    verdict = "PASSED" if passed else "REJECTED"
    print(f"[GATE 2 {verdict}] "
          f"{sum(s['status'] == PASS for s in stages)} pass / "
          f"{sum(s['status'] == FAIL for s in stages)} fail / "
          f"{sum(s['status'] == SKIPPED for s in stages)} skipped"
          f"{' (strict: skipped stages block deploy)' if strict and any_skipped else ''}")
    return {"passed": passed, "strict": strict, "stages": stages}


def main():
    parser = argparse.ArgumentParser(description="AES Gate 2 — Compile-Boot-Diff harness")
    parser.add_argument("source", help="patched C source file to validate")
    parser.add_argument("--allow-skips", action="store_true",
                        help="diagnostics only: permit skipped stages; result is not deployable")
    args = parser.parse_args()

    result = run_gate2(Path(args.source), strict=not args.allow_skips)
    print("\n--- GATE 2 OUTPUT RESULT ---")
    print(json.dumps(result, indent=4))
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
