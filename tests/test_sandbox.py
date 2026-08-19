"""
Unit tests for the skill sandbox + injector: FP-gate honesty, demo-incident
exclusion, and injector status enforcement (REVIEW P1-6, P2-16).
Run: pytest tests/test_sandbox.py
"""
import hashlib
import hmac
import json

from skills.sandbox import Sandbox
from skills.schema import BenchmarkResult, Skill, PENDING_HITL
from skills.inject import Injector


def _write(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


_LABEL_KEY = "test-benchmark-label-key-32-chars-minimum"


def _signed(sample_id, ground_truth, deviations, **extra):
    row = {
        "sample_id": sample_id,
        "ground_truth": ground_truth,
        "deviations": deviations,
        **extra,
    }
    bound = {key: row[key] for key in ("sample_id", "ground_truth", "deviations")}
    row["label_signature"] = hmac.new(
        _LABEL_KEY.encode(),
        json.dumps(bound, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    return row


def test_fp_gate_fails_without_normal_corpus(tmp_path, monkeypatch):
    monkeypatch.setenv("AES_BENCHMARK_HMAC_KEY", _LABEL_KEY)
    inc = tmp_path / "inc.jsonl"; norm = tmp_path / "norm.jsonl"
    _write(inc, [_signed("attack-1", "ATTACK", {"cpu": 1.0, "packet_rate": 1.0})])
    norm.write_text("")   # no normal corpus
    skill = Skill(params={"deviation_threshold": 0.5, "simultaneous_threshold": 2})
    result = Sandbox(inc, norm).benchmark(skill)
    assert not result.passed()   # unmeasured FP rate must not certify


def test_demo_incidents_excluded_from_attack_corpus(tmp_path, monkeypatch):
    monkeypatch.setenv("AES_BENCHMARK_HMAC_KEY", _LABEL_KEY)
    inc = tmp_path / "inc.jsonl"; norm = tmp_path / "norm.jsonl"
    _write(inc, [
        _signed("demo-1", "ATTACK", {"cpu": 0.1}, demo=True),
        _signed("attack-1", "ATTACK", {"cpu": 1.0, "packet_rate": 1.0}),
    ])
    _write(norm, [_signed("normal-1", "NORMAL", {"cpu": 0.0})])
    skill = Skill(params={"deviation_threshold": 0.5, "simultaneous_threshold": 2})
    result = Sandbox(inc, norm).benchmark(skill)
    # Only the one real attack counts, and it is caught → 100% detection.
    assert result.detection_rate == 1.0


def test_elevated_band_can_fail_fp_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("AES_BENCHMARK_HMAC_KEY", _LABEL_KEY)
    # An over-tight skill flags benign elevated readings → high FP → rejected.
    inc = tmp_path / "inc.jsonl"; norm = tmp_path / "norm.jsonl"
    _write(inc, [_signed("attack-1", "ATTACK", {"cpu": 1.0, "packet_rate": 1.0})])
    _write(norm, [_signed("normal-1", "NORMAL", {"cpu": 0.4, "memory": 0.4})])
    tight = Skill(params={"deviation_threshold": 0.30, "simultaneous_threshold": 2})
    result = Sandbox(inc, norm).benchmark(tight)
    assert result.false_positive_rate > 0.10
    assert not result.passed()


def test_unsigned_detector_labels_cannot_certify_skill(tmp_path, monkeypatch):
    monkeypatch.setenv("AES_BENCHMARK_HMAC_KEY", _LABEL_KEY)
    inc = tmp_path / "inc.jsonl"; norm = tmp_path / "norm.jsonl"
    _write(inc, [{"sample_id": "attack-1", "ground_truth": "ATTACK",
                  "deviations": {"cpu": 1.0, "packet_rate": 1.0}}])
    _write(norm, [{"sample_id": "normal-1", "ground_truth": "NORMAL",
                   "deviations": {"cpu": 0.0}}])
    result = Sandbox(inc, norm).benchmark(
        Skill(params={"deviation_threshold": 0.5, "simultaneous_threshold": 2})
    )
    assert result.attack_sample_size == 0
    assert result.normal_sample_size == 0
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
    monkeypatch.setenv("AES_SKILL_APPROVAL_KEY", "test-skill-approval-key-32-chars-minimum")
    skill = Skill(
        params={"deviation_threshold": 0.4, "simultaneous_threshold": 2},
        benchmark=BenchmarkResult(
            detection_rate=1.0, false_positive_rate=0.0,
            sample_size=2, attack_sample_size=1, normal_sample_size=1,
        ),
    )
    skill.approve("test-operator")
    assert Injector(store=None).inject(skill) is True
    assert json.loads(active.read_text())["deviation_threshold"] == 0.4


def test_skill_approval_refuses_unbenchmarked_or_tampered_params(monkeypatch):
    monkeypatch.setenv("AES_SKILL_APPROVAL_KEY", "test-skill-approval-key-32-chars-minimum")
    unbenchmarked = Skill(params={"deviation_threshold": 0.4, "simultaneous_threshold": 2})
    try:
        unbenchmarked.approve("operator")
    except ValueError as exc:
        assert "benchmark" in str(exc)
    else:
        raise AssertionError("unbenchmarked skill was approved")

    approved = Skill(
        params={"deviation_threshold": 0.4, "simultaneous_threshold": 2},
        benchmark=BenchmarkResult(
            detection_rate=1.0, false_positive_rate=0.0,
            sample_size=2, attack_sample_size=1, normal_sample_size=1,
        ),
    )
    approved.approve("operator")
    approved.params["deviation_threshold"] = 0.8
    assert not approved.approval_is_valid()
