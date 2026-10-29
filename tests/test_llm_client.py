"""Unit tests for the OpenAI Responses API compatibility wrapper."""

from types import SimpleNamespace

import pytest

from agents.llm_client import LLMBackendError, _OpenAIMessages


class _FakeResponses:
    def __init__(self, output_text="ok"):
        self.output_text = output_text
        self.request = None

    def create(self, **kwargs):
        self.request = kwargs
        return SimpleNamespace(output_text=self.output_text)


def test_openai_wrapper_uses_responses_api_and_preserves_roles():
    responses = _FakeResponses("  accepted  ")
    client = SimpleNamespace(responses=responses)
    wrapper = _OpenAIMessages(client, "gpt-5.6-sol")

    result = wrapper.create(
        system="trusted policy",
        messages=[{"role": "user", "content": "analyze"}],
        max_tokens=10,
        timeout=12,
    )

    assert result.content[0].text == "accepted"
    assert responses.request == {
        "model": "gpt-5.6-sol",
        "input": [{"role": "user", "content": "analyze"}],
        "max_output_tokens": 256,
        "timeout": 12,
        "instructions": "trusted policy",
    }


def test_openai_wrapper_honors_per_call_model_and_rejects_empty_output():
    responses = _FakeResponses("")
    wrapper = _OpenAIMessages(SimpleNamespace(responses=responses), "default")

    with pytest.raises(LLMBackendError, match="empty output"):
        wrapper.create(model="patch-model", messages=[], max_tokens=1024)

    assert responses.request["model"] == "patch-model"
    assert responses.request["max_output_tokens"] == 1024


# ─── Backend chain (Claude + Codex working together) ─────────────────────────

from agents import llm_client as lc  # noqa: E402


class _Backend:
    def __init__(self, name, reply=None, error=None):
        self.name = name
        self.model = f"{name}-model"
        self.calls = []
        self._reply, self._error = reply, error
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self._error:
            raise self._error
        return SimpleNamespace(content=[SimpleNamespace(text=self._reply)])


def test_chain_hands_failed_request_to_next_backend():
    claude = _Backend("claude-cli", error=lc.ClaudeCLIError("not logged in"))
    codex = _Backend("codex", reply="verdict")
    chain = lc.BackendChain([claude, codex])

    result = chain.messages.create(model="ignored", max_tokens=5, messages=[{"role": "user", "content": "x"}])

    assert result.content[0].text == "verdict"
    assert chain.last_backend == "codex:codex-model"
    # The same request reached both, without the provider-specific model name.
    assert claude.calls == codex.calls == [{"max_tokens": 5, "messages": [{"role": "user", "content": "x"}]}]


def test_chain_raises_backend_error_when_every_backend_fails():
    chain = lc.BackendChain([
        _Backend("claude", error=lc.LLMBackendError("down")),
        _Backend("codex", error=lc.CodexCLIError("down")),
    ])
    with pytest.raises(lc.LLMBackendError, match="all reasoning backends failed"):
        chain.messages.create(messages=[])
    assert chain.last_backend is None


def test_chain_does_not_hide_programming_errors():
    chain = lc.BackendChain([_Backend("claude", error=KeyError("bug")), _Backend("codex", reply="x")])
    with pytest.raises(KeyError):
        chain.messages.create(messages=[])


def test_empty_chain_raises_backend_error():
    with pytest.raises(lc.LLMBackendError, match="no backend is configured"):
        lc.BackendChain([]).messages.create(messages=[])


def _clear_backend_env(monkeypatch):
    for key in ("HERMES_BACKEND", "HERMES_CODE_BACKEND", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                "AES_PRODUCTION", "AES_ALLOW_AGENTIC_LLM", "HERMES_CLI_MODEL",
                "HERMES_CLAUDE_CLI_MODEL"):
        monkeypatch.delenv(key, raising=False)


def _fake_path(monkeypatch, *present):
    monkeypatch.setattr(lc.shutil, "which", lambda exe: f"/usr/bin/{exe}" if exe in present else None)


def test_auto_selection_puts_claude_first_for_reasoning_and_codex_first_for_code(monkeypatch):
    _clear_backend_env(monkeypatch)
    _fake_path(monkeypatch, "claude", "codex")

    reasoning = lc.make_hermes_client()
    code = lc.make_hermes_client(role="code")

    assert [b.name for b in reasoning.backends] == ["claude-cli", "codex"]
    assert [b.name for b in code.backends] == ["codex", "claude-cli"]


def test_explicit_order_is_respected_and_unavailable_backends_skipped(monkeypatch):
    _clear_backend_env(monkeypatch)
    _fake_path(monkeypatch, "codex")
    monkeypatch.setenv("HERMES_BACKEND", "claude-cli, codex")

    chain = lc.make_hermes_client()

    assert [b.name for b in chain.backends] == ["codex"]


def test_production_refuses_explicit_agentic_cli_backend(monkeypatch):
    _clear_backend_env(monkeypatch)
    _fake_path(monkeypatch, "claude", "codex")
    monkeypatch.setenv("AES_PRODUCTION", "1")
    monkeypatch.setenv("HERMES_BACKEND", "claude-cli")
    with pytest.raises(lc.LLMBackendError, match="disabled in production"):
        lc.make_hermes_client()

    monkeypatch.setenv("HERMES_BACKEND", "auto")
    assert lc.make_hermes_client().backends == []   # CLIs silently excluded in auto mode

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("HERMES_BACKEND", "claude,codex")
    assert [b.name for b in lc.make_hermes_client().backends] == ["claude"]   # codex skipped
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.setenv("HERMES_BACKEND", "auto")

    monkeypatch.setenv("AES_ALLOW_AGENTIC_LLM", "1")
    assert [b.name for b in lc.make_hermes_client().backends] == ["claude-cli", "codex"]


def test_anthropic_wrapper_sends_system_and_joins_text_blocks():
    seen = {}

    class _Msgs:
        def create(self, **kwargs):
            seen.update(kwargs)
            return SimpleNamespace(content=[
                SimpleNamespace(type="thinking", text="hidden"),
                SimpleNamespace(type="text", text=" {\"action\": "),
                SimpleNamespace(type="text", text="\"PATCH_OTA\"} "),
            ])

    wrapper = lc._AnthropicMessages(SimpleNamespace(messages=_Msgs()), "claude-opus-5-5")
    result = wrapper.create(system="policy", messages=[{"role": "user", "content": "go"}],
                            max_tokens=10, timeout=7)

    assert result.content[0].text == '{"action": "PATCH_OTA"}'
    assert seen == {"model": "claude-opus-5-5", "max_tokens": 256, "timeout": 7,
                    "system": "policy", "messages": [{"role": "user", "content": "go"}]}


def test_anthropic_wrapper_rejects_empty_output():
    class _Msgs:
        def create(self, **kwargs):
            return SimpleNamespace(content=[])
    with pytest.raises(lc.LLMBackendError, match="empty output"):
        lc._AnthropicMessages(SimpleNamespace(messages=_Msgs()), "m").create(messages=[])


def _fake_claude(monkeypatch, help_text="  --safe-mode   Start with all customizations off",
                 reply=" pong \n", returncode=0, stderr=""):
    calls = []

    def fake_run(cmd, **kwargs):
        if cmd[1:] == ["--help"]:
            return SimpleNamespace(returncode=0, stdout=help_text, stderr="")
        prompt_file = cmd[cmd.index("--system-prompt-file") + 1] if "--system-prompt-file" in cmd else None
        calls.append({"cmd": cmd, "kwargs": kwargs,
                      "system": open(prompt_file, encoding="utf-8").read() if prompt_file else None})
        return SimpleNamespace(returncode=returncode, stdout=reply, stderr=stderr)

    lc._CLAUDE_SAFE_MODE_SUPPORT.clear()
    monkeypatch.setattr(lc.shutil, "which", lambda exe: "/usr/bin/claude")
    monkeypatch.setattr(lc.subprocess, "run", fake_run)
    monkeypatch.delenv("HERMES_CLAUDE_CLI_MODEL", raising=False)
    return calls


def test_claude_cli_runs_isolated_without_tools_or_secrets(monkeypatch):
    calls = _fake_claude(monkeypatch)
    monkeypatch.setenv("AES_DEPLOY_APPROVAL_KEY", "secret-that-must-not-leak")
    monkeypatch.setenv("HOME", "/home/test")

    system = "line one\nline \"two\" & %PATH% ^"
    result = lc.ClaudeCLIClient().messages.create(
        system=system, messages=[{"role": "user", "content": "ping"}], timeout=30)

    assert result.content[0].text == "pong"
    call = calls[0]
    cmd = call["cmd"]
    assert cmd[:2] == ["/usr/bin/claude", "-p"]
    assert "--safe-mode" in cmd                          # no personal hooks/plugins/CLAUDE.md
    assert cmd[cmd.index("--tools") + 1] == ""          # every built-in tool disabled
    assert "--system-prompt" not in cmd                  # prompt never travels as an argument
    assert call["system"] == system                      # multi-line prompt arrives intact
    assert "--strict-mcp-config" in cmd and "--no-session-persistence" in cmd
    assert call["kwargs"]["input"] == "ping"
    env = call["kwargs"]["env"]
    assert "AES_DEPLOY_APPROVAL_KEY" not in env and env["HOME"] == "/home/test"


def test_claude_cli_without_safe_mode_is_refused(monkeypatch):
    calls = _fake_claude(monkeypatch, help_text="  --print   Print response and exit")
    with pytest.raises(lc.ClaudeCLIError, match="no --safe-mode"):
        lc.ClaudeCLIClient().messages.create(messages=[{"role": "user", "content": "x"}])
    assert calls == []                                   # never ran the prompt


def test_claude_cli_nonzero_exit_is_backend_error(monkeypatch):
    _fake_claude(monkeypatch, reply="", returncode=1, stderr="auth required")
    with pytest.raises(lc.ClaudeCLIError, match="auth required"):
        lc.ClaudeCLIClient().messages.create(messages=[{"role": "user", "content": "x"}])
