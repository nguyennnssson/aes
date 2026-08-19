"""
Unit tests for Hermes verdict hardening: action allowlist + confidence clamp
(REVIEW P0-3) and the offline-fallback confidence cap (REVIEW P1-5).
Run: pytest tests/test_hermes.py
"""
import json
from types import SimpleNamespace

import pytest

from agents.hermes import Hermes, IncidentVerdict


class _FakeClient:
    """Duck-types the backend `.messages.create` interface for one canned reply."""
    def __init__(self, reply_text):
        self.model = "test-model"
        self._reply = reply_text
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        return SimpleNamespace(content=[SimpleNamespace(text=self._reply)])


def _hermes(reply):
    return Hermes(client=_FakeClient(reply))


def test_valid_action_passes_through():
    h = _hermes(json.dumps({"action": "PATCH_OTA", "cve_id": "CVE-2026-0001", "confidence": 0.9}))
    v = h.analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.action == "PATCH_OTA" and v.confidence == 0.9


def test_unknown_action_coerced_to_held_investigate():
    h = _hermes(json.dumps({"action": "rm -rf /", "confidence": 0.99}))
    v = h.analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.action == "INVESTIGATE" and v.confidence == 0.0


def test_confidence_clamped_to_unit_interval():
    h = _hermes(json.dumps({"action": "PATCH_OTA", "cve_id": "CVE-2026-0001", "confidence": 5.0}))
    v = h.analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.confidence == 1.0


def test_nonfinite_confidence_is_held():
    h = _hermes(json.dumps({"action": "PATCH_OTA", "cve_id": "CVE-2026-0001", "confidence": float("nan")}))
    v = h.analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.confidence == 0.0


def test_action_must_match_trusted_solution_track():
    h = _hermes(json.dumps({"action": "BLOCK_FIREWALL", "cve_id": "CVE-2026-0001", "confidence": 0.99}))
    v = h.analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.action == "INVESTIGATE" and v.confidence == 0.0


def test_unparseable_response_is_held():
    h = _hermes("not json at all")
    v = h.analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.action == "INVESTIGATE" and v.confidence == 0.0


def test_fallback_confidence_capped_below_hold_threshold(monkeypatch):
    import agents.fallback as fb

    class _Resp:
        def raise_for_status(self): pass
        def json(self):
            return {"message": {"content": json.dumps(
                {"action": "PATCH_OTA", "cve_id": "CVE-9", "confidence": 0.99})}}

    monkeypatch.setattr(fb.requests, "post", lambda *a, **k: _Resp())
    monkeypatch.setattr(fb.subprocess, "run", lambda *a, **k: None)
    v = fb.OllamaFallback().analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.confidence < 0.5   # never auto-executes: lands in respond()'s hold
