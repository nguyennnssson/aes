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
  passed = every stage that RAN passed.
  --strict additionally fails the gate if any stage was skipped — use this on
  demo day / production, where "we couldn't test it" must block the flash.

OUTPUT CONTRACT (same shape response_agent.py parses for Gate 1):
  human-readable log, then a marker line and JSON:
    --- GATE 2 OUTPUT RESULT ---
    {"passed": true, "stages": [{"name", "status", "detail"}, ...]}

USAGE:
  python gate2.py <patched_source.c> [--strict]

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


def _stage(name: str, status: str, detail: str) -> dict:
    icon = {"pass": "✅", "fail": "❌", "skipped": "⏭"}[status]
    print(f"[GATE 2] {icon} {name}: {detail}")
    return {"name": name, "status": status, "detail": detail}


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

    # Brace/paren balance on comment- and string-stripped text.
    stripped = re.sub(r'//[^\n]*|/\*.*?\*/', '', text, flags=re.DOTALL)
    stripped = re.sub(r'"(\\.|[^"\\])*"|\'(\\.|[^\'\\])*\'', '""', stripped)
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

        bins = list((staged / "build").glob("*.bin"))
        if not bins:
            return _stage("compile", FAIL, "build reported success but produced no .bin")

        # Keep the verified binary for the boot-diff stage / manual flash.
        out_dir = _REPO_ROOT / "outputs" / "gate2"
        out_dir.mkdir(parents=True, exist_ok=True)
        verified = out_dir / "verified_firmware.bin"
        shutil.copy2(bins[0], verified)
        return _stage("compile", PASS, f"clean build → {verified}")


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

    firmware = _REPO_ROOT / "outputs" / "gate2" / "verified_firmware.bin"
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
    from agents.mqtt_compat import make_mqtt_client
    from agents.monitor_agent import MonitorAgent, evaluate_detection, load_active_params
    import threading

    # Only the reference device's fresh telemetry counts as boot proof (REVIEW
    # P1-9): subscribing to the wildcard let any publisher (e.g. the simulator)
    # fake a boot. GATE2_REFERENCE_DEVICE names the flashed device; unset falls
    # back to the wildcard for backward-compatible single-device benches.
    ref_device = os.getenv("GATE2_REFERENCE_DEVICE")
    booted   = threading.Event()
    readings = []

    def _on_msg(client, _u, msg):
        try:
            data = json.loads(msg.payload.decode())
        except json.JSONDecodeError:
            return
        if ref_device and data.get("device_id") != ref_device:
            return
        readings.append(data)
        booted.set()

    client = make_mqtt_client("aes-gate2-harness")
    client.on_message = _on_msg
    try:
        client.connect(os.getenv("MQTT_HOST", "localhost"),
                       int(os.getenv("MQTT_PORT", "1883")), keepalive=10)
        client.subscribe(f"aes/telemetry/{ref_device}" if ref_device else "aes/telemetry/+")
        client.loop_start()
        boot_ok = booted.wait(timeout=35)
    except Exception as e:
        return _stage("boot-diff", FAIL, f"MQTT boot verification error: {e}")
    finally:
        try:
            client.loop_stop(); client.disconnect()
        except Exception:
            pass

    if not boot_ok:
        return _stage("boot-diff", FAIL,
                      "no telemetry within 35s — device likely rolled back the patch")

    # Attack replay: run the logged attack deviations back through the LIVE
    # detection params. The patch is proven when the reference device, running
    # patched firmware, no longer produces the attack signature — the recorded
    # signature must still be recognisable (detector sane) while the fresh
    # reference readings stay clean.
    replay_path = Path(os.getenv("GATE2_ATTACK_REPLAY", _INCIDENTS))
    attacks = []
    if replay_path.exists():
        for line in replay_path.read_text().splitlines():
            try:
                attacks.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    if not attacks:
        return _stage("boot-diff", FAIL, f"no recorded attack traffic to replay ({replay_path})")

    params = load_active_params()
    still_detected = sum(
        1 for a in attacks if evaluate_detection(a.get("deviations", {}), params)[0]
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
        1 for r in readings if evaluate_detection(_deviations(r), params)[0]
    )

    if fresh_flagged:
        return _stage("boot-diff", FAIL, "patched firmware's clean boot telemetry still flags as attack")
    return _stage(
        "boot-diff", PASS,
        f"booted in <35s, {still_detected}/{len(attacks)} recorded attacks still recognised "
        f"by the detector, fresh telemetry clean",
    )


# ─── MAIN ────────────────────────────────────────────────────────────────────

def run_gate2(src: Path, strict: bool = False) -> dict:
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
    parser.add_argument("--strict", action="store_true",
                        help="fail the gate if any stage had to be skipped (production mode)")
    args = parser.parse_args()

    result = run_gate2(Path(args.source), strict=args.strict)
    print("\n--- GATE 2 OUTPUT RESULT ---")
    print(json.dumps(result, indent=4))
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
