"""
AES — Ollama Offline Fallback
==============================

Activated when the OpenAI reasoning backend is unreachable (connection or timeout).
Exposes the same analyze_incident() signature as Hermes so the swap is transparent.

Model: llama3:8b-instruct-q4_K_M via Ollama (local, never co-resident with live path)
  - Loaded on demand, unloaded after use to preserve unified memory for ChromaDB.
  - Pull once: ollama pull llama3:8b-instruct-q4_K_M

Limitations vs Hermes:
  - No patch generation (generate_patch not implemented)
  - Reduced reasoning depth
  - Confidence capped at 0.5 to signal degraded mode to operators

Usage: instantiated inside hermes.py — not called directly.
"""

import json
import subprocess
import requests
from agents.hermes import IncidentVerdict

OLLAMA_URL     = "http://localhost:11434/api/chat"
FALLBACK_MODEL = "llama3:8b-instruct-q4_K_M"


class OllamaFallback:

    def analyze_incident(
        self,
        device_id:      str,
        anomaly_reason: str,
        intel_context:  str,
        solution_track: int,
    ) -> IncidentVerdict:
        """
        Same signature as Hermes.analyze_incident().
        Called automatically by Hermes when the OpenAI backend is unreachable.
        """
        print(f"[FALLBACK] OpenAI backend unreachable — using local Llama 3 8B")

        prompt = (
            f"You are a security AI. Analyze this IoT attack and respond in JSON only.\n\n"
            f"Device: {device_id}\n"
            f"Anomaly: {anomaly_reason}\n"
            f"Solution Track: {solution_track}\n\n"
            f"Intel (truncated):\n{intel_context[:500]}\n\n"
            f"Respond with JSON only:\n"
            f'{{"action":"PATCH_OTA|BLOCK_FIREWALL|REWRITE_SKILL|INVESTIGATE",'
            f'"cve_id":"CVE-XXXX-XXXX or UNKNOWN",'
            f'"confidence":0.0-1.0,'
            f'"reasoning":"one sentence explanation"}}'
        )

        try:
            r = requests.post(
                OLLAMA_URL,
                json={
                    "model":   FALLBACK_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream":  False,
                },
                timeout=60,
            )
            r.raise_for_status()
            raw = r.json()["message"]["content"].strip()
            parsed = self._parse_json(raw)
        except Exception as e:
            print(f"[FALLBACK] Ollama call failed: {e}")
            parsed = {}
        finally:
            # Unload model after use to free unified memory for ChromaDB
            self._unload_model()

        return IncidentVerdict(
            solution_track = solution_track,
            action         = parsed.get("action", "INVESTIGATE"),
            cve_id         = parsed.get("cve_id", "UNKNOWN"),
            # Cap confidence at 0.49 so a degraded (local Llama) verdict ALWAYS
            # lands in respond()'s `confidence < 0.5` MANUAL_REVIEW hold rather
            # than auto-executing remediation (REVIEW P1-5).
            confidence = min(float(parsed.get("confidence", 0.3) or 0.3), 0.49),
            reasoning      = f"[OFFLINE FALLBACK] {parsed.get('reasoning', 'OpenAI backend unreachable — local inference only')}",
        )

    def _parse_json(self, raw: str) -> dict:
        try:
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw)
        except (json.JSONDecodeError, IndexError):
            return {}

    def _unload_model(self):
        """Stop the Ollama model after use to free unified memory."""
        try:
            subprocess.run(
                ["ollama", "stop", FALLBACK_MODEL],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass   # non-critical — process cleanup, don't crash on failure
