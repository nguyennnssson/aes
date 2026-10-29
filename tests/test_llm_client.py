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


def test_claude_cli_runs_without_tools_or_secrets(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"], captured["kwargs"] = cmd, kwargs
        return SimpleNamespace(returncode=0, stdout=" pong \n", stderr="")

    monkeypatch.setattr(lc.shutil, "which", lambda exe: "/usr/bin/claude")
    monkeypatch.setattr(lc.subprocess, "run", fake_run)
    monkeypatch.setenv("AES_DEPLOY_APPROVAL_KEY", "secret-that-must-not-leak")
    monkeypatch.setenv("HOME", "/home/test")
    monkeypatch.delenv("HERMES_CLAUDE_CLI_MODEL", raising=False)

    result = lc.ClaudeCLIClient().messages.create(
        system="policy", messages=[{"role": "user", "content": "ping"}], timeout=30)

    assert result.content[0].text == "pong"
    cmd = captured["cmd"]
    assert cmd[:2] == ["/usr/bin/claude", "-p"]
    assert cmd[cmd.index("--tools") + 1] == ""          # every built-in tool disabled
    assert cmd[cmd.index("--system-prompt") + 1] == "policy"
    assert "--strict-mcp-config" in cmd and "--no-session-persistence" in cmd
    assert captured["kwargs"]["input"] == "ping"
    env = captured["kwargs"]["env"]
    assert "AES_DEPLOY_APPROVAL_KEY" not in env and env["HOME"] == "/home/test"


def test_claude_cli_nonzero_exit_is_backend_error(monkeypatch):
    monkeypatch.setattr(lc.shutil, "which", lambda exe: "/usr/bin/claude")
    monkeypatch.setattr(lc.subprocess, "run",
                        lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="", stderr="auth required"))
    with pytest.raises(lc.ClaudeCLIError, match="auth required"):
        lc.ClaudeCLIClient().messages.create(messages=[{"role": "user", "content": "x"}])
