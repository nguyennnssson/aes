"""
AES — Hermes LLM Client Factory
================================

Hermes only needs `client.messages.create(...)` returning `.content[0].text`,
so the model provider is swappable. Four backends are implemented:

  claude      — Anthropic Messages API via the official `anthropic` SDK.
                Needs ANTHROPIC_API_KEY. Model: HERMES_CLAUDE_MODEL
                (default `claude-opus-5-5`).
  claude-cli  — the locally installed Claude Code CLI (`claude -p`) in
                non-interactive print mode with --safe-mode (no personal hooks,
                plugins, CLAUDE.md) and every built-in tool disabled.
                Authenticates with the user's Claude login; no key required.
                Model: HERMES_CLAUDE_CLI_MODEL (default: the CLI's own default).
  openai      — OpenAI Responses API via the official `openai` SDK.
                Needs OPENAI_API_KEY. Models: HERMES_MODEL (reasoning) and
                HERMES_CODE_MODEL (patch generation), default `gpt-5.6-sol`.
  codex       — the locally installed Codex CLI (`codex exec`) in a read-only
                sandbox. Authenticates with a ChatGPT login; no key required.
                Model: HERMES_CLI_MODEL (default: the CLI's own default).

Two roles, each with an ordered backend chain
---------------------------------------------
  HERMES_BACKEND       — reasoning: incident verdicts, packet-window
                         classification, detector tuning proposals.
  HERMES_CODE_BACKEND  — firmware patch generation.

Each value is a comma-separated, ordered list, e.g.

  HERMES_BACKEND=claude-cli,codex        # Claude reasons, Codex backs it up
  HERMES_CODE_BACKEND=codex,claude-cli   # Codex writes patches, Claude backs it up

The chain calls the first backend; if that backend errors (missing binary,
missing key, network error, timeout, empty output, provider API error) the same
request goes to the next backend. Only when every backend in the chain fails
does Hermes drop to the local Ollama Llama 3 fallback (agents/fallback.py).

Unset / `auto` picks every backend that is configured on this machine:
  reasoning: claude → claude-cli → openai → codex
  code:      openai → codex → claude → claude-cli
A backend counts as configured when its API key is set (claude, openai) or its
CLI is on PATH (claude-cli, codex).

The CLI backends drive agentic tools, so with AES_PRODUCTION=1 they are skipped
unless an operator sets AES_ALLOW_AGENTIC_LLM=1 after reviewing that risk (and
construction fails if they were the only backends requested).

Usage:
    from agents.llm_client import make_hermes_client
    hermes = Hermes(client=make_hermes_client(),
                    code_client=make_hermes_client(role="code"))
"""

import os
import shutil
import subprocess
import tempfile
from types import SimpleNamespace


class LLMBackendError(Exception):
    """A reasoning-backend call failed (missing binary or key, non-zero exit,
    timeout, empty output, or a provider API error)."""


class CodexCLIError(LLMBackendError):
    """The `codex` CLI call failed specifically."""


class ClaudeCLIError(LLMBackendError):
    """The `claude` CLI call failed specifically."""


def is_backend_error(exc: Exception) -> bool:
    """True if `exc` is a provider/backend failure that should move the request
    to the next backend (or, at the end of the chain, to the offline fallback).
    Programming errors (TypeError, KeyError, ...) are NOT backend errors and
    still raise, so bugs are never hidden behind a fallback."""
    if isinstance(exc, LLMBackendError):
        return True
    try:
        import openai
        if isinstance(exc, openai.OpenAIError):
            return True
    except ImportError:
        pass
    try:
        import anthropic
        if isinstance(exc, anthropic.AnthropicError):
            return True
    except ImportError:
        pass
    return False


def _response(text: str):
    return SimpleNamespace(content=[SimpleNamespace(text=text)])


# ─── OPENAI SDK BACKEND (Responses API) ──────────────────────────────────────

class _OpenAIMessages:
    """Duck-types the `.messages.create(...) -> .content[0].text` interface over
    the OpenAI Responses API so Hermes' call sites need no changes."""

    def __init__(self, client, model: str):
        self._client = client
        self.model = model

    def create(self, model=None, max_tokens=None, system=None, messages=None,
               timeout=30.0, **_ignored):
        input_messages = list(messages or [])

        # Reasoning tokens draw from the output budget, so a tiny cap (e.g. 10
        # for one-word classification) can starve the visible answer. Floor the
        # budget to leave room for the reply.
        budget = max(int(max_tokens or 512), 256)

        request = {
            "model": model or self.model,
            "input": input_messages,
            "max_output_tokens": budget,
            "timeout": timeout,
        }
        if system:
            request["instructions"] = system
        resp = self._client.responses.create(
            **request,
        )
        text = (resp.output_text or "").strip()
        if not text:
            raise LLMBackendError("OpenAI Responses API returned empty output")
        return _response(text)


class OpenAIClient:
    """openai.OpenAI()-backed client (`gpt-5.6-sol` by default)."""

    name = "openai"

    def __init__(self, model: str = None):
        import openai
        self._sdk = openai
        self.client = openai.OpenAI()  # reads OPENAI_API_KEY
        self.model = model or os.getenv("HERMES_MODEL", "gpt-5.6-sol")
        self.messages = _OpenAIMessages(self.client, self.model)

    def __repr__(self):
        return f"OpenAIClient(model={self.model!r})"


# ─── ANTHROPIC SDK BACKEND (Messages API) ────────────────────────────────────

class _AnthropicMessages:
    """`.messages.create(...) -> .content[0].text` over the Anthropic Messages API.
    Only text blocks are returned; the system prompt is passed as `system`."""

    def __init__(self, client, model: str):
        self._client = client
        self.model = model

    def create(self, model=None, max_tokens=None, system=None, messages=None,
               timeout=30.0, **_ignored):
        # Same floor as the OpenAI wrapper so a one-word classification call
        # (max_tokens=10) cannot be truncated mid-token.
        request = {
            "model": model or self.model,
            "max_tokens": max(int(max_tokens or 512), 256),
            "messages": list(messages or []),
            "timeout": timeout,
        }
        if system:
            request["system"] = system
        resp = self._client.messages.create(**request)
        text = "".join(
            getattr(block, "text", "") for block in (resp.content or [])
            if getattr(block, "type", "text") == "text"
        ).strip()
        if not text:
            raise LLMBackendError("Anthropic Messages API returned empty output")
        return _response(text)


class ClaudeAPIClient:
    """anthropic.Anthropic()-backed client (`claude-opus-5-5` by default)."""

    name = "claude"

    def __init__(self, model: str = None):
        import anthropic
        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        self.model = model or os.getenv("HERMES_CLAUDE_MODEL", "claude-opus-5-5")
        self.messages = _AnthropicMessages(self.client, self.model)

    def __repr__(self):
        return f"ClaudeAPIClient(model={self.model!r})"


# ─── CLI BACKENDS (subscription login, no API key) ───────────────────────────

# Environment variables an isolated CLI subprocess may see. Application secrets
# from .env (MQTT, HMAC, dashboard, webhook keys) are never passed through;
# the CLI authenticates from its own login stored under the user profile.
_CLI_ENV_KEEP = {
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
    "HOME", "USER", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
    "XDG_CONFIG_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "LANG", "TERM",
}


def _cli_env() -> dict:
    return {key: value for key, value in os.environ.items() if key.upper() in _CLI_ENV_KEEP}


def _cli_timeout(timeout) -> float:
    # CLI startup + reasoning is slower than a raw API call; scale the caller's
    # API-sized timeout up but keep it bounded so the monitor thread can never
    # hang on a wedged subprocess.
    return max(120.0, float(timeout or 30.0) * 4)


def _user_prompt(messages) -> str:
    # Hermes only ever sends user messages; join them in order.
    return "\n\n".join(m["content"] for m in (messages or []) if m.get("role") == "user")


class _CodexMessages:
    """Duck-types `.messages.create(...) -> .content[0].text` over the `codex exec`
    CLI (one non-interactive turn).

    Key details verified against codex-cli 0.142.5:
      * `-o/--output-last-message FILE` writes ONLY the final assistant message to
        FILE. stdout additionally carries session UI ("codex", "tokens used"), so
        we read the FILE, not stdout.
      * `--skip-git-repo-check` + `--sandbox read-only` keep this a pure one-shot
        reasoning/generation call (no repo mutation, no approval prompts).
      * The MODEL is left to Codex's own config by default. A ChatGPT-account login
        only supports the models OpenAI enables for it. Set HERMES_CLI_MODEL only
        to a model your login actually supports; otherwise Codex uses its
        configured default."""

    def __init__(self, model_override):
        self.model_override = model_override    # None → use Codex's configured model
        self._exe = shutil.which("codex")

    def create(self, model=None, max_tokens=None, system=None, messages=None,
               timeout=30.0, **_ignored):
        if not self._exe:
            raise CodexCLIError("codex CLI not found on PATH — install the Codex CLI "
                                "(and run `codex login`) or configure another backend")

        # The per-call `model` (meant for an API backend) is intentionally
        # IGNORED here — the CLI uses Codex's own configured model unless
        # HERMES_CLI_MODEL overrides it. A system prompt is folded into the input.
        user = _user_prompt(messages)
        prompt = f"{system}\n\n{user}" if system else user
        cli_timeout = _cli_timeout(timeout)

        with tempfile.TemporaryDirectory(prefix="hermes-isolated-") as workspace:
            out_file = os.path.join(workspace, "last-message.txt")
            cmd = [
                self._exe, "exec", "--skip-git-repo-check", "--sandbox", "read-only",
                "--ephemeral", "--ignore-user-config", "--ignore-rules",
                "-C", workspace, "-o", out_file,
            ]
            if self.model_override:
                cmd += ["--model", self.model_override]
            cmd += ["-"]

            try:
                proc = subprocess.run(
                    cmd, input=prompt, capture_output=True, text=True, cwd=workspace,
                    encoding="utf-8", errors="replace", timeout=cli_timeout, env=_cli_env(),
                )
            except subprocess.TimeoutExpired:
                raise CodexCLIError(f"codex CLI timed out after {cli_timeout:.0f}s")
            except OSError as e:
                raise CodexCLIError(f"codex CLI failed to launch: {e}")

            text = ""
            try:
                with open(out_file, encoding="utf-8", errors="replace") as f:
                    text = f.read().strip()
            except OSError:
                pass
        if not text:
            text = (proc.stdout or "").strip()

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[-400:]
            raise CodexCLIError(f"codex CLI exited {proc.returncode}: {detail}")
        if not text:
            raise CodexCLIError("codex CLI returned empty output")
        return _response(text)


class CodexCLIClient:
    """`.messages.create()`-shaped wrapper around `codex exec` (ChatGPT subscription
    auth). The model comes from Codex's own config unless HERMES_CLI_MODEL overrides
    it (a ChatGPT login rejects models it isn't entitled to)."""

    name = "codex"

    def __init__(self):
        self.model_override = os.getenv("HERMES_CLI_MODEL") or None
        self.model = self.model_override or "(codex config default)"
        self.messages = _CodexMessages(self.model_override)

    def __repr__(self):
        return f"CodexCLIClient(model={self.model!r})"


_CLAUDE_SAFE_MODE_SUPPORT: dict = {}


def _claude_supports_safe_mode(exe: str) -> bool:
    """True if this `claude` binary offers --safe-mode (checked once per path)."""
    if exe not in _CLAUDE_SAFE_MODE_SUPPORT:
        try:
            proc = subprocess.run(
                [exe, "--help"], capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30, env=_cli_env(),
            )
            _CLAUDE_SAFE_MODE_SUPPORT[exe] = "--safe-mode" in (proc.stdout or "")
        except (OSError, subprocess.TimeoutExpired):
            return False   # not cached: a transient failure may succeed later
    return _CLAUDE_SAFE_MODE_SUPPORT[exe]


class _ClaudeCLIMessages:
    """`.messages.create(...) -> .content[0].text` over `claude -p` (Claude Code
    print mode), one non-interactive turn.

    Flags (checked against Claude Code 2.1.x `claude --help`):
      * `-p --output-format text` prints only the final reply.
      * `--safe-mode` starts with every customization off: CLAUDE.md, skills,
        plugins, hooks, MCP servers, custom commands and agents. Without it the
        operator's personal Claude Code setup would run hooks and inject context
        into every security verdict. A CLI without --safe-mode is refused, so
        the chain moves on to the next backend.
      * `--tools ""` disables every built-in tool, so the call cannot run
        commands, read files, or edit anything — pure text in, text out.
      * `--strict-mcp-config` with no `--mcp-config` loads no MCP servers.
      * `--no-session-persistence` keeps nothing on disk after the call.
      * `--system-prompt-file` replaces Claude Code's default agent prompt with
        the Hermes system prompt. A file (not an argument) keeps the multi-line
        prompt intact when Windows launches an npm `claude.cmd` shim.
    The call runs in an empty temporary directory with the scrubbed CLI env."""

    def __init__(self, model_override):
        self.model_override = model_override    # None → the CLI's default model
        self._exe = shutil.which("claude")

    def create(self, model=None, max_tokens=None, system=None, messages=None,
               timeout=30.0, **_ignored):
        if not self._exe:
            raise ClaudeCLIError("claude CLI not found on PATH — install Claude Code "
                                 "(and log in) or configure another backend")
        if not _claude_supports_safe_mode(self._exe):
            raise ClaudeCLIError("installed claude CLI has no --safe-mode, so personal "
                                 "hooks/plugins cannot be isolated — update Claude Code")

        # As with Codex, the per-call API `model` is ignored; the CLI uses
        # HERMES_CLAUDE_CLI_MODEL or its own default.
        prompt = _user_prompt(messages)
        cli_timeout = _cli_timeout(timeout)
        cmd = [
            self._exe, "-p", "--output-format", "text", "--safe-mode", "--tools", "",
            "--strict-mcp-config", "--no-session-persistence",
        ]
        if self.model_override:
            cmd += ["--model", self.model_override]

        with tempfile.TemporaryDirectory(prefix="hermes-isolated-") as workspace:
            if system:
                prompt_file = os.path.join(workspace, "system-prompt.md")
                with open(prompt_file, "w", encoding="utf-8") as f:
                    f.write(system)
                cmd += ["--system-prompt-file", prompt_file]
            try:
                proc = subprocess.run(
                    cmd, input=prompt, capture_output=True, text=True, cwd=workspace,
                    encoding="utf-8", errors="replace", timeout=cli_timeout, env=_cli_env(),
                )
            except subprocess.TimeoutExpired:
                raise ClaudeCLIError(f"claude CLI timed out after {cli_timeout:.0f}s")
            except OSError as e:
                raise ClaudeCLIError(f"claude CLI failed to launch: {e}")

        text = (proc.stdout or "").strip()
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[-400:]
            raise ClaudeCLIError(f"claude CLI exited {proc.returncode}: {detail}")
        if not text:
            raise ClaudeCLIError("claude CLI returned empty output")
        return _response(text)


class ClaudeCLIClient:
    """`.messages.create()`-shaped wrapper around `claude -p` (Claude login, no
    API key). HERMES_CLAUDE_CLI_MODEL optionally pins a model (e.g. `opus`)."""

    name = "claude-cli"

    def __init__(self):
        self.model_override = os.getenv("HERMES_CLAUDE_CLI_MODEL") or None
        self.model = self.model_override or "(claude config default)"
        self.messages = _ClaudeCLIMessages(self.model_override)

    def __repr__(self):
        return f"ClaudeCLIClient(model={self.model!r})"


# ─── BACKEND CHAIN ───────────────────────────────────────────────────────────

class _ChainMessages:
    def __init__(self, chain: "BackendChain"):
        self._chain = chain

    def create(self, model=None, **kwargs):
        # A per-call `model` names a model of ONE provider; it cannot be sent to
        # the others. Members always use their own configured model.
        chain = self._chain
        errors = []
        for backend in chain.backends:
            try:
                result = backend.messages.create(**kwargs)
            except Exception as exc:
                if not is_backend_error(exc):
                    raise
                errors.append(f"{backend.name}: {exc}")
                print(f"[HERMES] {chain.role} backend {backend.name} failed ({exc})"
                      + (" — trying next backend" if backend is not chain.backends[-1] else ""))
                continue
            chain.last_backend = f"{backend.name}:{backend.model}"
            return result
        chain.last_backend = None
        detail = "; ".join(errors) if errors else "no backend is configured"
        raise LLMBackendError(f"all {chain.role} backends failed — {detail}")


class BackendChain:
    """Ordered list of backends behind the single `.messages.create` interface.
    `last_backend` records which provider answered the most recent call, so a
    verdict can be attributed to the model that actually produced it."""

    def __init__(self, backends: list, role: str = "reasoning"):
        self.backends = list(backends)
        self.role = role
        self.last_backend = None
        self.model = " → ".join(f"{b.name}:{b.model}" for b in self.backends) or "(none)"
        self.messages = _ChainMessages(self)

    def __repr__(self):
        return f"BackendChain(role={self.role!r}, backends={self.model!r})"


# ─── FACTORY ─────────────────────────────────────────────────────────────────

_ALIASES = {
    "claude": "claude", "anthropic": "claude",
    "claude-cli": "claude-cli", "claude_cli": "claude-cli", "claude-code": "claude-cli",
    "openai": "openai", "api": "openai",
    "codex": "codex", "cli": "codex",   # 'cli' kept for older .env files
    "auto": "auto",
}
_AUTO_ORDER = {
    "reasoning": ["claude", "claude-cli", "openai", "codex"],
    "code":      ["openai", "codex", "claude", "claude-cli"],
}
_AGENTIC = {"claude-cli", "codex"}


def _available(name: str) -> tuple[bool, str]:
    if name == "claude":
        return bool(os.getenv("ANTHROPIC_API_KEY")), "ANTHROPIC_API_KEY is unset"
    if name == "openai":
        return bool(os.getenv("OPENAI_API_KEY")), "OPENAI_API_KEY is unset"
    if name == "claude-cli":
        return bool(shutil.which("claude")), "`claude` is not on PATH"
    if name == "codex":
        return bool(shutil.which("codex")), "`codex` is not on PATH"
    return False, "unknown backend"


def _parse_backend_list(raw: str, role: str) -> tuple[list, bool]:
    """Return (ordered backend names, explicitly_requested)."""
    names = []
    for part in (raw or "").split(","):
        part = part.strip().lower()
        if not part:
            continue
        name = _ALIASES.get(part)
        if name is None:
            print(f"[HERMES] Ignoring unknown backend {part!r} in {role} backend list")
            continue
        if name == "auto":
            names.extend(_AUTO_ORDER[role])
        else:
            names.append(name)
    explicit = bool(names) and "auto" not in (raw or "").lower()
    if not names:
        names = list(_AUTO_ORDER[role])
    deduped = []
    for name in names:
        if name not in deduped:
            deduped.append(name)
    return deduped, explicit


def _build(name: str, role: str):
    if name == "claude":
        return ClaudeAPIClient()
    if name == "claude-cli":
        return ClaudeCLIClient()
    if name == "openai":
        model = os.getenv("HERMES_CODE_MODEL" if role == "code" else "HERMES_MODEL", "gpt-5.6-sol")
        return OpenAIClient(model=model)
    if name == "codex":
        return CodexCLIClient()
    raise ValueError(name)


def make_hermes_client(role: str = "reasoning") -> BackendChain:
    """Build the backend chain for `role` ("reasoning" or "code").

    Reads HERMES_BACKEND (reasoning) or HERMES_CODE_BACKEND (code). An explicitly
    listed backend that is not configured is skipped with a warning; if no
    backend is usable the chain still returns, and every call raises
    LLMBackendError so Hermes uses the offline Ollama fallback."""
    if role not in _AUTO_ORDER:
        raise ValueError("role must be 'reasoning' or 'code'")
    env_name = "HERMES_CODE_BACKEND" if role == "code" else "HERMES_BACKEND"
    names, explicit = _parse_backend_list(os.getenv(env_name, ""), role)

    production = os.getenv("AES_PRODUCTION") == "1"
    agentic_allowed = os.getenv("AES_ALLOW_AGENTIC_LLM") == "1"

    backends = []
    refused = []
    for name in names:
        if name in _AGENTIC and production and not agentic_allowed:
            refused.append(name)
            if explicit:
                print(f"[HERMES] Skipping {role} backend {name}: agentic CLI backends are "
                      "disabled when AES_PRODUCTION=1 (set AES_ALLOW_AGENTIC_LLM=1 after review)")
            continue
        ok, reason = _available(name)
        if not ok:
            if explicit:
                print(f"[HERMES] Skipping {role} backend {name}: {reason}")
            continue
        try:
            backends.append(_build(name, role))
        except ImportError as exc:
            print(f"[HERMES] Skipping {role} backend {name}: SDK not installed ({exc})")

    if explicit and refused and not backends:
        # Fail loudly rather than silently running on the offline fallback when
        # the operator asked only for backends that production forbids.
        raise LLMBackendError(
            f"{', '.join(refused)} {'is an agentic CLI backend' if len(refused) == 1 else 'are agentic CLI backends'} "
            "and disabled in production; use claude/openai API backends or explicitly set "
            "AES_ALLOW_AGENTIC_LLM=1 after risk review"
        )

    chain = BackendChain(backends, role=role)
    if backends:
        print(f"[HERMES] {role} backends: {chain.model}")
    else:
        print(f"[HERMES] No {role} backend is configured — calls will use the offline fallback")
    return chain
