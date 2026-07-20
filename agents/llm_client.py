"""
AES — Hermes LLM Client Factory
================================

Hermes only needs `client.messages.create(...)` returning `.content[0].text`,
so the reasoning backend is swappable. Two OpenAI-based backends:

  openai — the official `openai` SDK, needs a live OPENAI_API_KEY. Reasoning
           runs on GPT-5 (HERMES_MODEL); firmware patch generation runs on
           Codex (HERMES_CODE_MODEL, default `gpt-5-codex`).
  codex  — the locally installed `codex` CLI in non-interactive `exec` mode,
           which authenticates with a ChatGPT subscription login instead of an
           API key. No key required.

Selection (env HERMES_BACKEND):
  HERMES_BACKEND=openai → force the OpenAI SDK
  HERMES_BACKEND=codex  → force the Codex CLI
  unset                 → openai if OPENAI_API_KEY is set, else codex

Why two models? Codex (`gpt-5-codex`) is tuned for writing and iterating on code
against compilers/linters — exactly what `Hermes.generate_patch()` does inside
the Gate 1/Gate 2 loop. GPT-5 handles the pure-reasoning calls (incident
verdicts, packet classification, self-tuning detection params).

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


# ─── OPENAI SDK BACKEND (GPT-5 reasoning + Codex patch generation) ────────────

class _OpenAIMessages:
    """Duck-types the `.messages.create(...) -> .content[0].text` interface over
    the OpenAI Chat Completions API so Hermes' call sites need no changes."""

    def __init__(self, client, model: str):
        self._client = client
        self.model = model

    def create(self, model=None, max_tokens=None, system=None, messages=None,
               timeout=30.0, **_ignored):
        chat = []
        if system:
            chat.append({"role": "system", "content": system})
        chat.extend(messages or [])

        # GPT-5 is a reasoning model: reasoning tokens draw from the completion
        # budget, so a tiny cap (e.g. 10 for one-word classification) can starve
        # the visible answer. Floor the budget to leave room for the reply.
        budget = max(int(max_tokens or 512), 256)

        resp = self._client.chat.completions.create(
            model=model or self.model,
            messages=chat,
            max_completion_tokens=budget,
            timeout=timeout,
        )
        text = (resp.choices[0].message.content or "").strip()
        return SimpleNamespace(content=[SimpleNamespace(text=text)])


class OpenAIClient:
    """openai.OpenAI()-backed reasoning client (GPT-5 by default)."""

    def __init__(self, model: str = None):
        import openai
        self._sdk = openai
        self.client = openai.OpenAI()  # reads OPENAI_API_KEY
        self.model = model or os.getenv("HERMES_MODEL", "gpt-5")
        self.messages = _OpenAIMessages(self.client, self.model)

    def __repr__(self):
        return f"OpenAIClient(model={self.model!r})"


# ─── CODEX CLI BACKEND (ChatGPT subscription auth, no API key) ────────────────

class _CodexMessages:
    """Duck-types `.messages.create(...)` over the `codex exec` CLI, which runs a
    single non-interactive turn and prints the result to stdout.

    NOTE: verify the flags against your installed `codex` version — the CLI's
    surface evolves. `codex exec <prompt>` runs headless; `--model` selects the
    model. Mirrors the subscription-auth pattern the OpenAI SDK backend replaces
    with an API key."""

    def __init__(self, model: str):
        self.model = model
        self._exe = shutil.which("codex")

    def create(self, model=None, max_tokens=None, system=None, messages=None,
               timeout=30.0, **_ignored):
        if not self._exe:
            raise CodexCLIError("codex CLI not found on PATH — install the Codex "
                                "CLI or set HERMES_BACKEND=openai with a live key")

        # Hermes only ever sends a single user message; fold any system prompt in.
        user = "\n\n".join(m["content"] for m in (messages or [])
                           if m.get("role") == "user")
        prompt = f"{system}\n\n{user}" if system else user

        cmd = [self._exe, "exec", "--model", model or self.model, "-"]

        # CLI startup + reasoning is slower than a raw API call; scale the
        # caller's API-sized timeout up but keep it bounded so the monitor
        # thread can never hang on a wedged subprocess.
        cli_timeout = max(120.0, float(timeout or 30.0) * 4)

        try:
            proc = subprocess.run(
                cmd, input=prompt, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=cli_timeout,
            )
        except subprocess.TimeoutExpired:
            raise CodexCLIError(f"codex CLI timed out after {cli_timeout:.0f}s")
        except OSError as e:
            raise CodexCLIError(f"codex CLI failed to launch: {e}")

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[-400:]
            raise CodexCLIError(f"codex CLI exited {proc.returncode}: {detail}")

        text = (proc.stdout or "").strip()
        if not text:
            raise CodexCLIError("codex CLI returned empty output")
        return SimpleNamespace(content=[SimpleNamespace(text=text)])


class CodexCLIClient:
    """`.messages.create()`-shaped wrapper around `codex exec` (subscription auth)."""

    def __init__(self, model: str = None):
        self.model = model or os.getenv("HERMES_CLI_MODEL", "gpt-5-codex")
        self.messages = _CodexMessages(self.model)

    def __repr__(self):
        return f"CodexCLIClient(model={self.model!r})"


def make_hermes_client():
    """Build the Hermes reasoning client per HERMES_BACKEND (see module docstring)."""
    backend = os.getenv("HERMES_BACKEND", "").strip().lower()
    if not backend:
        backend = "openai" if os.getenv("OPENAI_API_KEY") else "codex"

    if backend == "codex":
        client = CodexCLIClient()
        print(f"[HERMES] Backend: codex CLI (subscription auth) — model '{client.model}'")
        return client

    client = OpenAIClient()
    print(f"[HERMES] Backend: OpenAI API (OPENAI_API_KEY) — model '{client.model}'")
    return client
