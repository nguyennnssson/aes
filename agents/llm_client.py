"""
AES — Hermes LLM Client Factory
================================

Hermes only needs `client.messages.create(...)` returning `.content[0].text`,
so the reasoning backend is swappable. Two OpenAI-based backends:

  openai — the official `openai` SDK, needs a live OPENAI_API_KEY. Reasoning
           and firmware patch generation default to `gpt-5.6-sol`; the two
           roles remain independently configurable.
  codex  — the locally installed `codex` CLI in non-interactive `exec` mode,
           which authenticates with a ChatGPT subscription login instead of an
           API key. No key required.

Selection (env HERMES_BACKEND):
  HERMES_BACKEND=openai → force the OpenAI SDK
  HERMES_BACKEND=codex  → force the Codex CLI
  unset                 → openai if OPENAI_API_KEY is set, else codex

Why two settings? They let operators select and evaluate models independently
for security reasoning and firmware patch generation without changing code.

Usage:
    from agents.llm_client import make_hermes_client
    hermes = Hermes(client=make_hermes_client())
"""

import os
import shutil
import subprocess
import tempfile
from types import SimpleNamespace


class LLMBackendError(Exception):
    """A reasoning-backend call failed (missing binary, non-zero exit, or timeout).
    Hermes treats this like an API connection error and falls back to Ollama."""


class CodexCLIError(LLMBackendError):
    """The `codex` CLI call failed specifically."""


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
        return SimpleNamespace(content=[SimpleNamespace(text=text)])


class OpenAIClient:
    """openai.OpenAI()-backed reasoning client (`gpt-5.6-sol` by default)."""

    def __init__(self, model: str = None):
        import openai
        self._sdk = openai
        self.client = openai.OpenAI()  # reads OPENAI_API_KEY
        self.model = model or os.getenv("HERMES_MODEL", "gpt-5.6-sol")
        self.messages = _OpenAIMessages(self.client, self.model)

    def __repr__(self):
        return f"OpenAIClient(model={self.model!r})"


# ─── CODEX CLI BACKEND (ChatGPT subscription auth, no API key) ────────────────

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
        to a model your login
        actually supports; otherwise Codex uses its configured default."""

    def __init__(self, model_override):
        self.model_override = model_override    # None → use Codex's configured model
        self._exe = shutil.which("codex")

    def create(self, model=None, max_tokens=None, system=None, messages=None,
               timeout=30.0, **_ignored):
        if not self._exe:
            raise CodexCLIError("codex CLI not found on PATH — install the Codex CLI "
                                "(and run `codex login`) or set HERMES_BACKEND=openai with a key")

        # Hermes only ever sends a single user message; fold any system prompt in.
        # The per-call `model` (from HERMES_MODEL/HERMES_CODE_MODEL, meant for the
        # API backend) is intentionally IGNORED here — the CLI backend uses Codex's
        # own configured model unless HERMES_CLI_MODEL overrides it.
        user = "\n\n".join(m["content"] for m in (messages or [])
                           if m.get("role") == "user")
        prompt = f"{system}\n\n{user}" if system else user

        # CLI startup + reasoning is slower than a raw API call; scale the
        # caller's API-sized timeout up but keep it bounded so the monitor
        # thread can never hang on a wedged subprocess.
        cli_timeout = max(120.0, float(timeout or 30.0) * 4)

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

            # Do not pass application secrets from .env to an agentic subprocess.
            # Authentication remains available through CODEX_HOME/user profile.
            keep = {
                "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
                "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "CODEX_HOME",
                "LANG", "TERM",
            }
            child_env = {key: value for key, value in os.environ.items() if key.upper() in keep}
            try:
                proc = subprocess.run(
                    cmd, input=prompt, capture_output=True, text=True, cwd=workspace,
                    encoding="utf-8", errors="replace", timeout=cli_timeout, env=child_env,
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
        return SimpleNamespace(content=[SimpleNamespace(text=text)])


class CodexCLIClient:
    """`.messages.create()`-shaped wrapper around `codex exec` (ChatGPT subscription
    auth). The model comes from Codex's own config unless HERMES_CLI_MODEL overrides
    it (a ChatGPT login rejects models it isn't entitled to)."""

    def __init__(self):
        self.model_override = os.getenv("HERMES_CLI_MODEL") or None
        self.model = self.model_override or "(codex config default)"
        self.messages = _CodexMessages(self.model_override)

    def __repr__(self):
        return f"CodexCLIClient(model={self.model!r})"


def make_hermes_client():
    """Build the Hermes reasoning client per HERMES_BACKEND (see module docstring).

    Robust to legacy/unknown values: 'cli' (old Claude-era value) maps to codex,
    'api' to openai; anything empty or unrecognized auto-selects (openai if a key
    is present, else codex). If openai is requested without a key, we fall back to
    codex rather than crash — so a stale .env can never wedge the pipeline."""
    raw = os.getenv("HERMES_BACKEND", "").strip().lower()
    backend = {"cli": "codex", "codex": "codex", "api": "openai", "openai": "openai"}.get(raw, "")
    if not backend:
        backend = "openai" if os.getenv("OPENAI_API_KEY") else "codex"

    if backend == "openai" and not os.getenv("OPENAI_API_KEY"):
        print("[HERMES] HERMES_BACKEND=openai but OPENAI_API_KEY is unset — "
              "falling back to the codex CLI backend")
        backend = "codex"

    if backend == "codex":
        if os.getenv("AES_PRODUCTION") == "1" and os.getenv("AES_ALLOW_AGENTIC_LLM") != "1":
            raise LLMBackendError(
                "Codex CLI is agentic and disabled in production; use HERMES_BACKEND=openai "
                "or explicitly set AES_ALLOW_AGENTIC_LLM=1 after risk review"
            )
        client = CodexCLIClient()
        print(f"[HERMES] Backend: codex CLI (ChatGPT subscription auth) — model {client.model}")
        return client

    client = OpenAIClient()
    print(f"[HERMES] Backend: OpenAI API (OPENAI_API_KEY) — model '{client.model}'")
    return client
