"""
AES — Settings
==============
Loads .env and exposes a typed Settings dataclass.
All other modules import from here — no scattered os.getenv calls.

Usage:
    from config.settings import settings
    print(settings.hermes_model)
"""

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

# Load .env from repo root (works wherever the process is launched from)
_ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(_ENV_PATH)


@dataclass
class Settings:
    # OpenAI
    openai_api_key: str
    hermes_model: str        # reasoning model — gpt-5 (point at gpt-6 when available)
    hermes_code_model: str   # patch generation — Codex (gpt-5-codex)

    # ChromaDB
    chroma_persist_dir: str

    # MQTT
    mqtt_host: str
    mqtt_port: int

    # Discord
    discord_webhook_url: str

    # RAG ingestion
    nvd_api_key: str


def load() -> Settings:
    """Load settings from environment.

    OPENAI_API_KEY is NOT strictly required: with HERMES_BACKEND=codex, Hermes runs
    through the `codex` CLI (ChatGPT subscription auth) with no key. We only warn
    when neither a key nor the codex backend is configured, so importing this module
    can never crash a codex-backed process."""
    openai_api_key = os.getenv("OPENAI_API_KEY", "")
    backend = os.getenv("HERMES_BACKEND", "").strip().lower()
    if not openai_api_key and backend != "codex":
        print("[SETTINGS] Warning: no OPENAI_API_KEY and HERMES_BACKEND is not "
              "'codex' — Hermes will fall back to the codex CLI backend if available.")

    return Settings(
        openai_api_key      = openai_api_key,
        hermes_model        = os.getenv("HERMES_MODEL", "gpt-5"),
        hermes_code_model   = os.getenv("HERMES_CODE_MODEL", "gpt-5-codex"),
        chroma_persist_dir  = os.getenv("CHROMA_PERSIST_DIR", "./aes_chromadb"),
        mqtt_host           = os.getenv("MQTT_HOST", "localhost"),
        mqtt_port           = int(os.getenv("MQTT_PORT", "1883")),
        discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL", ""),
        nvd_api_key         = os.getenv("NVD_API_KEY", ""),
    )


# Module-level singleton — import this directly
settings = load()
