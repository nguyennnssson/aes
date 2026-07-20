# AES — Agents Package
# Contains all AI agent logic for the AES pipeline.
#
# Files:
#   monitor_agent.py      — Pure EWMA detection logic. No networking. Importable anywhere.
#   monitor_agent_mqtt.py — MQTT subscriber wrapper. Keep this running continuously.
#   response_agent.py     — Routes Hermes verdicts to Solution 1/2/3 handlers.
#   hermes.py             — GPT-5 reasoning layer (patch generation delegated to Codex).
#   llm_client.py         — Backend factory: OpenAI SDK (GPT-5 / Codex) or codex CLI.
#   intel_agent.py        — ChromaDB RAG query wrapper.
#   fallback.py           — Ollama offline fallback when the OpenAI backend is unreachable.
