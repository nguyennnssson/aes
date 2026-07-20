"""
Unit tests for the skill sandbox + injector: FP-gate honesty, demo-incident
exclusion, and injector status enforcement (REVIEW P1-6, P2-16).
Run: pytest tests/test_sandbox.py
"""
import json

from skills.sandbox import Sandbox
from skills.schema import Skill, BenchmarkResult, APPROVED, PENDING_HITL
from skills.inject import Injector


def _write(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_fp_gate_fails_without_normal_corpus(tmp_path):
    inc = tmp_path / "inc.jsonl"; norm = tmp_path / "norm.jsonl"
    _write(inc, [{"deviations": {"cpu": 1.0, "packet_rate": 1.0}}])
    norm.write_text("")   # no normal corpus
    skill = Skill(params={"deviation_threshold": 0.5, "simultaneous_threshold": 2})
    result = Sandbox(inc, norm).benchmark(skill)
    assert not result.passed()   # unmeasured FP rate must not certify


def test_demo_incidents_excluded_from_attack_corpus(tmp_path):
    inc = tmp_path / "inc.jsonl"; norm = tmp_path / "norm.jsonl"
    _write(inc, [
        {"demo": True, "deviations": {"cpu": 0.1}},           # fabricated, excluded
        {"deviations": {"cpu": 1.0, "packet_rate": 1.0}},     # real attack
    ])
    _write(norm, [{"status": "NORMAL", "deviations": {"cpu": 0.0}}])
    skill = Skill(params={"deviation_threshold": 0.5, "simultaneous_threshold": 2})
    result = Sandbox(inc, norm).benchmark(skill)
    # Only the one real attack counts, and it is caught → 100% detection.
    assert result.detection_rate == 1.0


def test_elevated_band_can_fail_fp_gate(tmp_path):
    # An over-tight skill flags benign elevated readings → high FP → rejected.
    inc = tmp_path / "inc.jsonl"; norm = tmp_path / "norm.jsonl"
    _write(inc, [{"deviations": {"cpu": 1.0, "packet_rate": 1.0}}])
    _write(norm, [{"status": "NORMAL", "deviations": {"cpu": 0.4, "memory": 0.4}}])
    tight = Skill(params={"deviation_threshold": 0.30, "simultaneous_threshold": 2})
    result = Sandbox(inc, norm).benchmark(tight)
    assert result.false_positive_rate > 0.10
    assert not result.passed()


def test_injector_refuses_non_approved(tmp_path, monkeypatch):
    import skills.inject as si
    monkeypatch.setattr(si, "_ACTIVE", tmp_path / "active.json")
    monkeypatch.setattr(si, "_PREVIOUS", tmp_path / "prev.json")
    skill = Skill(status=PENDING_HITL, params={"deviation_threshold": 0.4})
    assert Injector(store=None).inject(skill) is False   # not APPROVED
    assert not (tmp_path / "active.json").exists()


def test_injector_writes_approved(tmp_path, monkeypatch):
    import skills.inject as si
    active = tmp_path / "active.json"
    monkeypatch.setattr(si, "_ACTIVE", active)
    monkeypatch.setattr(si, "_PREVIOUS", tmp_path / "prev.json")
    skill = Skill(status=APPROVED, params={"deviation_threshold": 0.4, "simultaneous_threshold": 2})
    assert Injector(store=None).inject(skill) is True
    assert json.loads(active.read_text())["deviation_threshold"] == 0.4
