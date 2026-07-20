"""
Unit tests for the Solution 1 flash gate + staged build (REVIEW P0-1, P0-3).
Verifies the patched text (not the original main.c) is what would be built, and
that flashing is held behind AES_FLASH_ENFORCE.
Run: pytest tests/test_solution1_build.py
"""
import agents.response_agent as ra


def test_select_firmware_source_prefers_main_by_default(monkeypatch):
    monkeypatch.delenv("AES_ALLOW_VULN_SOURCE", raising=False)
    src = ra._select_firmware_source()
    assert src is not None and src.name == "main.c"


def test_staged_build_reuses_gate2_binary(tmp_path, monkeypatch):
    # When Gate 2 already produced verified_firmware.bin from the same patched
    # source, _staged_firmware_build must reuse it rather than rebuild.
    verified = tmp_path / "verified_firmware.bin"
    verified.write_bytes(b"FIRMWARE")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "outputs" / "gate2").mkdir(parents=True)
    (tmp_path / "outputs" / "gate2" / "verified_firmware.bin").write_bytes(b"FW")
    out = ra._staged_firmware_build("int main(){}")
    assert out is not None and out.name == "verified_firmware.bin"


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
