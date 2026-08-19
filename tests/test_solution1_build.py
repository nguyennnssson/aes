"""
Unit tests for the Solution 1 manifest-bound flash gate (REVIEW P0-1, P0-3).
Verifies insecure global build reuse is gone and flashing is held behind
AES_FLASH_ENFORCE.
Run: pytest tests/test_solution1_build.py
"""
import agents.response_agent as ra


def test_select_firmware_source_prefers_main_by_default(monkeypatch):
    monkeypatch.delenv("AES_ALLOW_VULN_SOURCE", raising=False)
    src = ra._select_firmware_source()
    assert src is not None and src.name == "main.c"


def test_global_verified_binary_reuse_is_removed():
    # Every incident must use the hash-bound artifact emitted by its own Gate 2
    # run. A shared verified_firmware.bin is a cross-incident substitution risk.
    assert not hasattr(ra, "_staged_firmware_build")


def test_flash_held_without_enforce(monkeypatch):
    # With AES_FLASH_ENFORCE unset, _flash_and_confirm must never be reached — but
    # here we assert the gate directly: flash_incident refuses without the flag.
    monkeypatch.delenv("AES_FLASH_ENFORCE", raising=False)
    assert ra.flash_incident("INC-DOES-NOT-MATTER") is False


def test_format_gate1_feedback():
    g1 = {"passed": False, "failures": [
        {"rule_id": "esp32-cwe119-buffer-overflow", "line": 5, "message": "unbounded strcpy"},
    ]}
    fb = ra._format_gate1_feedback(g1)
    assert "cwe119" in fb and "line 5" in fb and "strcpy" in fb
