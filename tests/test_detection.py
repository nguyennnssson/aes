"""
Unit tests for the pure detection core: EWMA snapshot rule, sustained low-and-slow
guard, MIN_BASELINE flooring, baseline freeze, telemetry validation, param
validation, and the tamper-evident log verifier (REVIEW P1-10, P1-11, P2-16).
Run: pytest tests/test_detection.py
"""
from datetime import datetime, timezone

import pytest

import agents.monitor_agent as ma
from agents.monitor_agent import (
    MonitorAgent, Telemetry, evaluate_detection, validate_detection_params,
)

DEV = "unit-test-device"   # not present in config/ewma_baseline.json → fresh state


def _t(cpu, mem, pkt, conn, device=DEV):
    return Telemetry(
        device_id=device,
        timestamp=datetime.now(timezone.utc).isoformat(),
        cpu_percent=cpu, memory_percent=mem, packet_rate=pkt, connection_count=conn,
    )


@pytest.fixture
def agent(monkeypatch):
    # Never touch the real committed baseline file during tests.
    monkeypatch.setattr(MonitorAgent, "_save_baseline", lambda self: None)
    monkeypatch.setattr(ma, "load_active_params", lambda: {})
    return MonitorAgent(DEV)


def _warm(agent, n=None):
    n = n or MonitorAgent.WARMUP_SAMPLES
    for _ in range(n):
        agent.check(_t(20, 40, 50, 3))


def test_warmup_suppresses_alerts(agent):
    for i in range(MonitorAgent.WARMUP_SAMPLES):
        r = agent.check(_t(20, 40, 50, 3))
        assert not r.is_anomaly
        assert r.reason.startswith("Warming")


def test_snapshot_rule_fires_on_two_metric_spike(agent):
    _warm(agent)
    r = agent.check(_t(90, 40, 500, 3))   # cpu + packet both far above baseline
    assert r.is_anomaly
    assert "ANOMALY" in r.reason


def test_single_metric_spike_does_not_fire(agent):
    _warm(agent)
    r = agent.check(_t(90, 40, 50, 3))    # only cpu spikes
    assert not r.is_anomaly


def test_min_baseline_prevents_low_baseline_false_positive(agent):
    # Warm up with ~zero packet rate so the learned baseline settles near 0.
    for _ in range(MonitorAgent.WARMUP_SAMPLES):
        agent.check(_t(20, 40, 0, 0))
    # A tiny absolute blip must not become a huge percentage spike.
    r = agent.check(_t(20, 40, 4, 0))
    assert not r.is_anomaly


def test_sustained_low_and_slow_guard(agent):
    _warm(agent)
    # Two metrics held ~40% over baseline (below the 0.5 snapshot threshold) for
    # the whole window → the sustained guard should fire.
    r = None
    for _ in range(MonitorAgent.SUSTAINED_WINDOW):
        r = agent.check(_t(28, 56, 50, 3))   # cpu +40%, memory +40%
    assert r.is_anomaly
    assert "SUSTAINED" in r.reason


def test_baseline_frozen_when_two_metrics_elevated(agent):
    _warm(agent)
    before = agent.ewma.cpu
    agent.check(_t(28, 56, 50, 3))   # 2 metrics >=30% → freeze, no baseline drift
    assert agent.ewma.cpu == before


def test_invalid_telemetry_rejected(agent):
    r = agent.check(_t(150, 40, 50, 3))   # cpu out of range
    assert not r.is_anomaly
    assert "INVALID" in r.reason


def test_empty_device_id_rejected():
    errs = _t(20, 40, 50, 3, device="").validate()
    assert any("device_id" in e for e in errs)


def test_evaluate_detection_shared_logic():
    devs = {"cpu": 0.6, "memory": 0.6, "packet_rate": 0.1, "connections": 0.0}
    fired, spiking = evaluate_detection(devs, {})
    assert fired and set(spiking) == {"cpu", "memory"}
    # Injected params tighten the threshold.
    fired2, _ = evaluate_detection({"cpu": 0.4, "memory": 0.4}, {"deviation_threshold": 0.35})
    assert fired2


def test_validate_detection_params_clamps_and_drops_junk():
    out = validate_detection_params({
        "deviation_threshold": 0.05,        # below floor → clamps to 0.30
        "simultaneous_threshold": 99,       # above cap → clamps to 4
        "bogus": "ignored",
        "junk_number": "not-a-float",
    })
    assert out == {"deviation_threshold": 0.30, "simultaneous_threshold": 4}
    assert validate_detection_params("not a dict") == {}
