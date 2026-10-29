# Model providers and fallback

How Hermes picks a model for each job and what happens when one fails.

"Hermes" (`agents/hermes.py`) and "OpenClaw" (`openclaw/`) are this project's
names for its reasoning and execution layers. They are plain Python modules and
do not use the external Hermes Agent or OpenClaw frameworks.

`agents/llm_client.py` implements four backends behind one interface:

| Backend | How it authenticates | Model setting |
|---|---|---|
| `claude` | Anthropic Messages API, `ANTHROPIC_API_KEY` | `HERMES_CLAUDE_MODEL` (default `claude-opus-5-5`) |
| `claude-cli` | Claude Code CLI login (`claude -p --safe-mode`, all tools disabled) | `HERMES_CLAUDE_CLI_MODEL` (default: CLI default) |
| `openai` | OpenAI Responses API, `OPENAI_API_KEY` | `HERMES_MODEL` / `HERMES_CODE_MODEL` (default `gpt-5.6-sol`) |
| `codex` | Codex CLI login (`codex exec`, read-only sandbox) | `HERMES_CLI_MODEL` (default: CLI default) |

Hermes has two roles, and each role has an ordered backend chain:

- `HERMES_BACKEND` — reasoning: incident verdicts, packet-window
  classification, detector-tuning proposals.
- `HERMES_CODE_BACKEND` — firmware patch generation.

```bash
HERMES_BACKEND=claude,codex        # Claude classifies and plans; Codex is the backup
HERMES_CODE_BACKEND=codex,claude   # Codex writes patches; Claude is the backup
```

With both unset (or `auto`), every configured backend is used in this order.
Reasoning tries `claude`, `claude-cli`, `openai`, then `codex`. Patch generation
tries `openai`, `codex`, `claude`, then `claude-cli`. A backend counts as
configured when its API key is set or its CLI is on `PATH`.

**How fallback is triggered.** The chain sends the request to the first backend.
The request moves to the next backend when the current one raises one of these:
a missing CLI or key, a non-zero CLI exit, a timeout (30 s for API verdicts,
60 s for patches, at least 120 s for CLIs), empty output, or any provider SDK
error (connection, authentication, rate limit, server error). A reply that is
not valid JSON does not trigger failover; it becomes a held `INVESTIGATE`
verdict with confidence 0. When every backend in the chain fails, Hermes calls
the local offline fallback in `agents/fallback.py`. That fallback is Llama 3 8B
(`llama3:8b-instruct-q4_K_M`) served by Ollama. Its confidence is capped at
0.49, so its verdicts always go to manual review, and it cannot generate patches.

Every verdict stores the backend that produced it in `verdict.backend` (for
example `claude-cli:opus` or `ollama:llama3:8b-instruct-q4_K_M`). Track 1 patch
manifests store it in `generated_by`.

Check every configured backend with one live prompt: `python scripts/check_backends.py`.

With `AES_PRODUCTION=1`, the CLI backends (`claude-cli`, `codex`) are skipped
because they drive agentic tools. Set `AES_ALLOW_AGENTIC_LLM=1` only after a
risk review. Both CLIs run in an empty temporary directory with a scrubbed
environment, so application secrets from `.env` are never passed to them. They
also ignore the operator's personal CLI setup: Codex runs with
`--ignore-user-config --ignore-rules`, and Claude Code runs with `--safe-mode`
(no hooks, plugins, skills, MCP servers, or CLAUDE.md). A Claude Code version
without `--safe-mode` is refused, and the request moves to the next backend.

[← Back to README](../README.md)
