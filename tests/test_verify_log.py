"""
Unit tests for verify_incident_log — must catch edits AND deletions (REVIEW P1-11).
Run: pytest tests/test_verify_log.py
"""
import hashlib
import json

import agents.monitor_agent as ma
from agents.monitor_agent import _incident_core, verify_incident_log


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
