"""Regression tests for input, filesystem, gate, and approval trust boundaries."""

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import agents.response_agent as ra
import gates.gate2 as gate2


def _receiver_module():
    path = Path(__file__).resolve().parents[1] / "raspberry-pi" / "receiver.py"
    spec = importlib.util.spec_from_file_location("aes_receiver_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _message(device_id: str, topic_device: str | None = None):
    payload = {
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": 20.0,
        "memory_percent": 40.0,
        "packet_rate": 50.0,
        "connection_count": 3,
    }
    return SimpleNamespace(
        topic=f"aes/telemetry/{topic_device or device_id}",
        payload=json.dumps(payload).encode("utf-8"),
    )


def test_receiver_rejects_path_traversal_device_id(tmp_path):
    receiver = _receiver_module()
    receiver.DATA_DIR = tmp_path / "telemetry"
    receiver.MIN_WRITE_INTERVAL = 0
    receiver.on_message(None, None, _message("../../outside"))
    assert not (tmp_path / "outside").exists()
    assert not receiver.DATA_DIR.exists()


def test_receiver_writes_only_inside_device_directory(tmp_path):
    receiver = _receiver_module()
    receiver.DATA_DIR = tmp_path / "telemetry"
    receiver.MIN_WRITE_INTERVAL = 0
    receiver.on_message(None, None, _message("esp32-cam-01"))
    latest = receiver.DATA_DIR / "esp32-cam-01" / "latest.json"
    assert json.loads(latest.read_text(encoding="utf-8"))["device_id"] == "esp32-cam-01"


def test_gate2_defaults_to_strict_when_stages_skip(tmp_path, monkeypatch):
    source = tmp_path / "main.c"
    source.write_text("int app_main(void) { return 0; }", encoding="utf-8")
    monkeypatch.setattr(gate2, "check_structure", lambda _src: gate2._stage("structure", gate2.PASS, "ok"))
    monkeypatch.setattr(gate2, "check_compile", lambda _src: gate2._stage("compile", gate2.SKIPPED, "no toolchain"))
    monkeypatch.setattr(gate2, "check_boot_diff", lambda _compile: gate2._stage("boot-diff", gate2.SKIPPED, "no hardware"))
    result = gate2.run_gate2(source)
    assert result["strict"] is True
    assert result["passed"] is False


def test_deployment_approval_binds_artifact_identity(monkeypatch):
    monkeypatch.setenv("AES_DEPLOY_APPROVAL_KEY", "test-deployment-approval-key-32-minimum")
    manifest = {
        "incident_id": "INC-1", "device_id": "d1", "patch_sha256": "a",
        "source_sha256": "b", "patched_source_sha256": "c",
        "binary_sha256": "d", "artifact_path": "outputs/gate2/INC-1/firmware.bin",
    }
    signature = ra._approval_signature(manifest)
    manifest["binary_sha256"] = "tampered"
    assert ra._approval_signature(manifest) != signature


def test_short_deployment_approval_key_is_refused(monkeypatch):
    monkeypatch.setenv("AES_DEPLOY_APPROVAL_KEY", "short")
    try:
        ra._approval_signature({})
    except ValueError as exc:
        assert "32" in str(exc)
    else:
        raise AssertionError("short approval key was accepted")
