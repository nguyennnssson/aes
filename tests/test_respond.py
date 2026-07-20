"""
Unit tests for response routing: INVESTIGATE / low-confidence / unknown-track
holds must NOT execute a remediation (REVIEW P0-3, H5). No network needed —
post_incident_alert no-ops without a webhook.
Run: pytest tests/test_respond.py
"""
import agents.response_agent as ra


def _incident():
    return {"incident_id": "INC-TEST-esp32-cam-01", "device_id": "esp32-cam-01",
            "device_model": "ESP32-CAM", "reason": "test", "detected_at": 0.0}


def _no_handler_calls(monkeypatch):
    called = {"n": 0}
    def handler(inc, ver):
        called["n"] += 1
        return True
    monkeypatch.setattr(ra, "SOLUTION_HANDLERS", {1: handler, 2: handler})
    # update_incident_status no-ops when the log file is absent; keep it inert.
    monkeypatch.setattr(ra, "update_incident_status", lambda *a, **k: None)
    monkeypatch.setattr(ra, "update_incident_fields", lambda *a, **k: None)
    return called


def test_investigate_is_held(monkeypatch):
    called = _no_handler_calls(monkeypatch)
    verdict = {"solution_track": 1, "action": "INVESTIGATE", "confidence": 0.9}
    assert ra.respond(_incident(), verdict) is False
    assert called["n"] == 0   # never executed a remediation


def test_low_confidence_is_held(monkeypatch):
    called = _no_handler_calls(monkeypatch)
    verdict = {"solution_track": 1, "action": "PATCH_OTA", "confidence": 0.3}
    assert ra.respond(_incident(), verdict) is False
    assert called["n"] == 0


def test_confidence_at_half_executes(monkeypatch):
    called = _no_handler_calls(monkeypatch)
    verdict = {"solution_track": 1, "action": "PATCH_OTA", "confidence": 0.5}
    assert ra.respond(_incident(), verdict) is True
    assert called["n"] == 1


def test_unknown_track_fails(monkeypatch):
    _no_handler_calls(monkeypatch)
    verdict = {"solution_track": 99, "action": "PATCH_OTA", "confidence": 0.9}
    assert ra.respond(_incident(), verdict) is False


def test_track1_runs_handler_once(monkeypatch):
    # Track 1 retries internally now, so respond() must call the handler once.
    called = _no_handler_calls(monkeypatch)
    monkeypatch.setattr(ra, "SOLUTION_HANDLERS", {1: lambda i, v: (called.__setitem__("n", called["n"] + 1) or False)})
    verdict = {"solution_track": 1, "action": "PATCH_OTA", "confidence": 0.9}
    assert ra.respond(_incident(), verdict) is False
    assert called["n"] == 1
