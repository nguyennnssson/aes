"""
Unit tests for Hermes verdict hardening: action allowlist, confidence clamp,
offline-fallback confidence cap, and backend attribution.
Run: pytest tests/test_hermes.py
"""
import json
from types import SimpleNamespace


from agents.hermes import Hermes


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


def test_verdict_records_which_backend_answered():
    from agents.llm_client import BackendChain, ClaudeCLIError

    class _Failing(_FakeClient):
        name = "claude-cli"
        def _create(self, **kwargs):
            raise ClaudeCLIError("offline")

    good = _FakeClient(json.dumps({"action": "PATCH_OTA", "cve_id": "CVE-2026-0001", "confidence": 0.9}))
    good.name = "codex"
    chain = BackendChain([_Failing("unused"), good])
    v = Hermes(client=chain).analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.action == "PATCH_OTA"
    assert v.backend == "codex:test-model"
    assert v.to_dict()["backend"] == "codex:test-model"


def test_whole_chain_failure_uses_offline_fallback(monkeypatch):
    import agents.fallback as fb
    from agents.llm_client import BackendChain

    monkeypatch.setattr(fb.requests, "post", lambda *a, **k: (_ for _ in ()).throw(OSError("no ollama")))
    monkeypatch.setattr(fb.subprocess, "run", lambda *a, **k: None)
    v = Hermes(client=BackendChain([])).analyze_incident("esp32-cam-01", "spike", "ctx", 1)
    assert v.reasoning.startswith("[OFFLINE FALLBACK]")
    assert v.backend.startswith("ollama:") and v.confidence < 0.5


def test_patch_generation_uses_code_client():
    reasoning = _FakeClient("reasoning-reply")
    code = _FakeClient("--- a/x\n+++ b/x\n")
    h = Hermes(client=reasoning, code_client=code)
    assert h.generate_patch("int x;", "ctx").startswith("--- a/x")


def test_model_chosen_investigate_keeps_its_reasoning():
    h = _hermes(json.dumps({"action": "INVESTIGATE", "cve_id": "UNKNOWN", "confidence": 0.3,
                            "reasoning": "Intel unavailable; need packet capture first."}))
    v = h.analyze_incident("esp32-cam-01", "spike", "INTEL UNAVAILABLE", 1)
    assert v.action == "INVESTIGATE"
    assert v.reasoning == "Intel unavailable; need packet capture first."
    assert v.confidence <= 0.49
