# Contributing to AES

Thanks for your interest in AES — Autonomous Edge-Sentinel. This guide covers
how to get a dev environment running and the conventions the project follows.

## Development setup

```bash
git clone https://github.com/nguyennnssson/aes.git
cd aes
python3.12 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp config/.env.example .env       # then fill in OPENAI_API_KEY (or use HERMES_BACKEND=codex)
```

See the [README](README.md) for the full stack (Mosquitto, Ollama, ChromaDB) and
the model/backend configuration.

## Running the tests

The unit suite is hermetic and offline (no API key or network required):

```bash
pytest tests/ -q
```

The full pipeline test (needs a local Mosquitto broker):

```bash
python scripts/test_pipeline.py
```

CI runs both on every pull request (`.github/workflows/`).

## Conventions

- **Match the surrounding style.** The codebase favors small, well-commented
  modules and explicit error handling over cleverness.
- **Interfaces are stable.** The telemetry JSON schema, the
  `handle_solution_1/2(incident, verdict) -> bool` contract, the unified-diff
  patch format, and the Gate 1/Gate 2 stdout markers are relied on across
  components — extend them additively (new optional fields), don't break them.
- **Safety defaults stay safe.** Physical actions (firmware flash, firewall
  writes) are opt-in behind environment flags. Keep the default path non-destructive.
- **No secrets in commits.** `.env` is gitignored; never commit API keys,
  webhooks, or device credentials. Runtime artifacts (incident logs, telemetry
  captures, generated patches) are gitignored too.

## Pull requests

1. Branch off `main`.
2. Keep changes focused; add or update tests for behavior changes.
3. Make sure `pytest tests/ -q` passes.
4. Open a PR with a clear description of what changed and why.

## Reporting bugs & vulnerabilities

Open a regular GitHub issue for bugs. For security vulnerabilities, please follow
[SECURITY.md](SECURITY.md) instead of filing a public issue.
