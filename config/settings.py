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
    # Model backends (see agents/llm_client.py for the chain semantics)
    hermes_backend: str       # reasoning chain, e.g. "claude-cli,codex"
    hermes_code_backend: str  # patch-generation chain, e.g. "codex,claude-cli"
    anthropic_api_key: str
    claude_model: str         # Claude API model
    openai_api_key: str
    hermes_model: str        # OpenAI reasoning model
    hermes_code_model: str   # OpenAI firmware patch-generation model

    # Local Intel vector index
    intel_db_path: str

    # MQTT
    mqtt_host: str
    mqtt_port: int

    # Discord
    discord_webhook_url: str

    # RAG ingestion
    nvd_api_key: str


def load() -> Settings:
    """Load settings from environment.

    No API key is strictly required: the claude-cli and codex backends use the
    local CLI logins, and with no usable backend Hermes falls back to local
    Llama 3. Importing this module therefore never crashes a process."""
    return Settings(
        hermes_backend      = os.getenv("HERMES_BACKEND", "auto"),
        hermes_code_backend = os.getenv("HERMES_CODE_BACKEND", "auto"),
        anthropic_api_key   = os.getenv("ANTHROPIC_API_KEY", ""),
        claude_model        = os.getenv("HERMES_CLAUDE_MODEL", "claude-opus-5-5"),
        openai_api_key      = os.getenv("OPENAI_API_KEY", ""),
        hermes_model        = os.getenv("HERMES_MODEL", "gpt-5.6-sol"),
        hermes_code_model   = os.getenv("HERMES_CODE_MODEL", "gpt-5.6-sol"),
        intel_db_path       = os.getenv("AES_INTEL_DB", "./data/aes_intel.sqlite3"),
        mqtt_host           = os.getenv("MQTT_HOST", "localhost"),
        mqtt_port           = int(os.getenv("MQTT_PORT", "8883")),
        discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL", ""),
        nvd_api_key         = os.getenv("NVD_API_KEY", ""),
    )


# Module-level singleton — import this directly
settings = load()
