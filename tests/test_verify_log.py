"""
Unit tests for verify_incident_log — must catch edits AND deletions (REVIEW P1-11).
Run: pytest tests/test_verify_log.py
"""
import hashlib
import json

import agents.monitor_agent as ma
from agents.monitor_agent import (
    AnomalyResult, _incident_core, initialize_incident_audit,
    verify_incident_log, write_incident_log,
)


def _seed(tmp_path, monkeypatch, incidents):
    log = tmp_path / "aes_incidents.jsonl"
    hashes = tmp_path / "aes_incidents.hashes"
    monkeypatch.setattr(ma, "LOG_PATH", log)
    monkeypatch.setattr(ma, "HASH_PATH", hashes)
    log.write_text("\n".join(json.dumps(e) for e in incidents) + "\n")
    hashes.write_text("\n".join(
        f"{e['incident_id']}:{hashlib.sha256(_incident_core(e).encode()).hexdigest()}"
        for e in incidents
    ) + "\n")
    return log, hashes


def _incident(iid):
    return {"incident_id": iid, "timestamp": "10:00:00", "device_id": "d1",
            "deviations": {"cpu": 1.0}, "status": "OPEN"}


def test_intact_log_verifies_ok(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, [_incident("INC-1"), _incident("INC-2")])
    assert verify_incident_log() == []


def test_status_edit_does_not_break_verification(tmp_path, monkeypatch):
    log, _ = _seed(tmp_path, monkeypatch, [_incident("INC-1")])
    e = _incident("INC-1"); e["status"] = "RESOLVED"; e["resolved_at"] = "10:05:00"
    log.write_text(json.dumps(e) + "\n")
    assert verify_incident_log() == []   # immutable core unchanged


def test_tampered_deviations_detected(tmp_path, monkeypatch):
    log, _ = _seed(tmp_path, monkeypatch, [_incident("INC-1")])
    e = _incident("INC-1"); e["deviations"] = {"cpu": 99.0}
    log.write_text(json.dumps(e) + "\n")
    problems = verify_incident_log()
    assert any("tampered" in p for p in problems)


def test_deleted_incident_detected(tmp_path, monkeypatch):
    log, _ = _seed(tmp_path, monkeypatch, [_incident("INC-1"), _incident("INC-2")])
    # Drop INC-2 from the log entirely — the ledger still lists it.
    log.write_text(json.dumps(_incident("INC-1")) + "\n")
    problems = verify_incident_log()
    assert any("INC-2" in p and "deleted" in p for p in problems)


def _event_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(ma, "LOG_PATH", tmp_path / "aes_incidents.jsonl")
    monkeypatch.setattr(ma, "HASH_PATH", tmp_path / "aes_incidents.hashes")
    monkeypatch.setattr(ma, "EVENT_PATH", tmp_path / "aes_incident_events.jsonl")
    monkeypatch.setattr(ma, "EVENT_HEAD_PATH", tmp_path / "aes_incident_events.head")
    monkeypatch.setenv("AES_AUDIT_HMAC_KEY", "test-audit-integrity-key-32-chars-minimum")


def test_authenticated_event_chain_covers_state_updates(tmp_path, monkeypatch):
    _event_paths(tmp_path, monkeypatch)
    result = AnomalyResult("d1", "2026-08-17T00:00:00+00:00", True, 0.9,
                           "test", {"cpu": 1.0}, {"cpu": 20.0})
    incident_id = write_incident_log(result, {"model": "test", "solution_track": 1})
    assert ma.update_incident_entry(incident_id, {"status": "AWAITING_APPROVAL"})
    assert verify_incident_log() == []

    lines = ma.EVENT_PATH.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[-1])
    event["payload"]["status"] = "RESOLVED"
    lines[-1] = json.dumps(event)
    ma.EVENT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("signature mismatch" in problem for problem in verify_incident_log())


def test_missing_audit_head_is_detected(tmp_path, monkeypatch):
    _event_paths(tmp_path, monkeypatch)
    result = AnomalyResult("d1", "2026-08-17T00:00:00+00:00", True, 0.9,
                           "test", {"cpu": 1.0}, {"cpu": 20.0})
    write_incident_log(result, {"model": "test", "solution_track": 1})
    ma.EVENT_HEAD_PATH.unlink()
    assert any("head missing" in problem for problem in verify_incident_log())


def test_legacy_history_is_verified_before_event_migration(tmp_path, monkeypatch):
    _event_paths(tmp_path, monkeypatch)
    log, _hashes = _seed(tmp_path, monkeypatch, [_incident("INC-1")])
    assert initialize_incident_audit(production=True) == []
    assert ma.EVENT_PATH.exists() and ma.EVENT_HEAD_PATH.exists()

    log.write_text(json.dumps({**_incident("INC-1"), "deviations": {"cpu": 99.0}}) + "\n")
    assert any("projection differs" in problem for problem in initialize_incident_audit(production=True))
