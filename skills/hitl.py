"""
AES — HITL (Human-in-the-Loop) Learning Loop Orchestrator
===========================================================
Owner: Son Nguyen (AI Infra)

Orchestrates Solution 3: the full learning loop from incident to live injection.

FLOW:
  Hermes detects a flaw in detection logic
    → propose_skill()   — Hermes generates improved detection code
    → sandbox.benchmark() — measure detection_rate, false_positive_rate
    → post to #aes-alerts — team sees proposed diff + benchmark
    → approve(skill_id)   — operator clicks ✅ in Discord or runs CLI
    → inject()            — hot-reload monitor agent with new detection code

TWO APPROVAL MODES:
  1. Manual CLI (Phase 0 / demo):
       python3 -m skills.hitl approve <skill_id>
     Operator sees Discord message, then runs this command to inject.

  2. Discord bot (future — Duc's task):
     Bot listens for ✅ reaction on the message, calls approve() automatically.
     Requires DISCORD_BOT_TOKEN env var.

Usage:
    from skills.hitl import HITLOrchestrator
    from agents.hermes import Hermes
    from agents.llm_client import make_hermes_client

    orchestrator = HITLOrchestrator(hermes=Hermes(client=make_hermes_client()))
    orchestrator.propose_skill(incident_id, device_id, anomaly_reason, intel_context)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


from agents.hermes import Hermes
from agents.intel_agent import IntelAgent
from discord.discord_alerts import post_learning_update
from skills.schema import Skill, APPROVED, PENDING_HITL
from skills.sandbox import Sandbox
from skills.store import SkillStore
from skills.inject import Injector


class HITLOrchestrator:

    def __init__(
        self,
        hermes: Hermes,
        store:  SkillStore = None,
    ):
        self.hermes   = hermes
        self.store    = store or SkillStore()
        self.sandbox  = Sandbox()
        self.injector = Injector(self.store)

    # ─── STEP 1: PROPOSE ─────────────────────────────────────────────────────

    def propose_skill(
        self,
        incident_id:    str,
        device_id:      str,
        anomaly_reason: str,
        intel_context:  str,
        cve_id:         str = "UNKNOWN",
        device_type:    str = "",
    ) -> Skill:
        """
        Ask Hermes to rewrite the detection logic based on this incident.
        Runs sandbox benchmark, posts to Discord for HITL approval.
        Returns the skill in PENDING_HITL state.
        """
        print(f"\n[HITL] Proposing skill for incident {incident_id}...")

        # Get current detection params as context for Hermes
        current_params = self._load_current_params()

        # Ask Hermes to propose tuned params
        new_params = self._call_hermes_tune(
            current_params = current_params,
            anomaly_reason = anomaly_reason,
            intel_context  = intel_context,
        )

        # Build the skill
        skill = Skill(
            incident_id      = incident_id,
            cve_id           = cve_id,
            device_type      = device_type,
            attack_signature = anomaly_reason[:200],
            params           = new_params,
            diff             = self._make_diff(current_params, new_params),
        )

        if not new_params:
            print("[HITL] ❌ Hermes returned no valid params — rejecting proposal")
            skill.reject()
            self.store.save(skill)
            return skill

        # Run sandbox benchmark
        benchmark = self.sandbox.benchmark(skill)

        if not benchmark.passed():
            print(f"[HITL] ❌ Skill failed sandbox — {benchmark.summary()} — not posting to Discord")
            skill.reject()
            self.store.save(skill)
            return skill

        # Post to Discord for HITL approval
        self._post_to_discord(skill)

        # Save as PENDING_HITL
        self.store.save(skill)
        print(f"[HITL] ⏳ Skill {skill.skill_id} posted to #aes-alerts — waiting for ✅")
        print(f"[HITL] To approve: python3 -m skills.hitl approve {skill.skill_id}")

        return skill

    # ─── STEP 2: APPROVE ─────────────────────────────────────────────────────

    def approve(self, skill_id: str, approved_by: str = "operator") -> bool:
        """
        Approve a pending skill and inject it live.
        Called manually (CLI) or by Discord bot on ✅ reaction.
        """
        skill = self.store.load_latest(skill_id)
        if not skill:
            print(f"[HITL] Skill {skill_id} not found")
            return False

        if skill.status != PENDING_HITL:
            print(f"[HITL] Skill {skill_id} is {skill.status}, not PENDING_HITL")
            return False

        skill.approve(approved_by)
        self.store.save(skill)

        print(f"[HITL] ✅ Approved by {approved_by} — injecting...")
        success = self.injector.inject(skill)

        if success:
            post_learning_update(skill, pending_approval=False)

        return success

    def reject(self, skill_id: str) -> bool:
        """Reject a pending skill (Discord ❌ or manual)."""
        skill = self.store.load_latest(skill_id)
        if not skill:
            print(f"[HITL] Skill {skill_id} not found")
            return False
        skill.reject()
        self.store.save(skill)
        print(f"[HITL] ❌ Skill {skill_id} rejected")
        return True

    # ─── PRIVATE ─────────────────────────────────────────────────────────────

    # Bounds keep Hermes (and a fat-fingered operator) from proposing absurd params.
    _PARAM_BOUNDS = {
        # Floor at 0.30: normal traffic jitters up to ~25-30%, so anything lower
        # causes false positives (and the sandbox would reject it). 0.30 still
        # catches throttled/stealth variants (~40% above baseline). This clamp
        # stops the loop from ratcheting into the false-positive zone.
        "deviation_threshold":    (0.30, 5.0),
        "simultaneous_threshold": (1, 4),
    }

    def _load_current_params(self) -> dict:
        """Load currently active detection params, or the monitor's defaults."""
        active = Path(__file__).parent.parent / "config" / "active_detection.json"
        if active.exists():
            try:
                return json.loads(active.read_text())
            except Exception:
                pass
        # Defaults mirror MonitorAgent class constants.
        return {"deviation_threshold": 0.5, "simultaneous_threshold": 2}

    def _call_hermes_tune(
        self,
        current_params: dict,
        anomaly_reason: str,
        intel_context:  str,
    ) -> dict:
        """
        Ask Hermes to propose improved EWMA detection params (JSON only).
        Returns a validated, clamped params dict, or {} if the response is unusable.
        """
        prompt = (
            f"DETECTION PARAMETER TUNING REQUEST\n\n"
            f"We just detected this attack. Consider whether a smart adversary could THROTTLE it to "
            f"sit just under our current threshold (a low-and-slow variant) and still do damage. If "
            f"so, propose a MODERATELY lower deviation_threshold that catches that throttled variant.\n\n"
            f"How detection works: a metric is flagged when it deviates >= deviation_threshold from "
            f"baseline; an anomaly needs >= simultaneous_threshold metrics flagged at once.\n\n"
            f"Constraints — read carefully:\n"
            f"- Normal traffic jitters up to ~25-30% above baseline, so NEVER set deviation_threshold "
            f"near or below that. Keep it >= 0.30 or you cause false alarms.\n"
            f"- A throttled variant of this attack class typically sits ~35-45% above baseline, so a "
            f"threshold around 0.30-0.40 is the sweet spot — catches the stealth variant, ignores jitter.\n"
            f"- If the current threshold is already in that safe 0.30-0.40 band, RETURN THE CURRENT "
            f"PARAMS UNCHANGED. Do not tighten for its own sake.\n"
            f"- A sandbox benchmark REJECTS any proposal that raises false positives, so overshooting "
            f"below 0.30 only gets your skill thrown out.\n\n"
            f"ATTACK SUMMARY:\n{anomaly_reason}\n\n"
            f"INTEL CONTEXT:\n{intel_context[:1000]}\n\n"
            f"CURRENT PARAMS: {json.dumps(current_params)}\n\n"
            f"Reply with JSON only — no prose, no markdown:\n"
            f'{{"deviation_threshold": <float 0.30-5.0>, "simultaneous_threshold": <int 1-4>}}'
        )

        try:
            msg = self.hermes.client.messages.create(
                model      = self.hermes.model,
                max_tokens = 128,
                messages   = [{"role": "user", "content": prompt}],
                timeout    = 30.0,
            )
            raw = self.hermes._parse_json(msg.content[0].text)
        except Exception as e:
            print(f"[HITL] Hermes tuning call failed: {e}")
            return {}

        return self._validate_params(raw)

    def _validate_params(self, raw: dict) -> dict:
        """Keep only known keys, coerce types, and clamp to safe bounds. Delegates
        to the shared validator so the live monitor and the learning loop agree on
        the exact bounds (REVIEW P2-16)."""
        from agents.monitor_agent import validate_detection_params
        return validate_detection_params(raw)

    def _make_diff(self, old_params: dict, new_params: dict) -> str:
        """Human-readable summary of the param change."""
        return f"params: {json.dumps(old_params)} → {json.dumps(new_params)}"

    def _post_to_discord(self, skill: Skill) -> None:
        """Post the proposed skill to #aes-alerts for HITL approval."""
        post_learning_update(skill, pending_approval=True)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    """
    CLI entry point for manual HITL approval.
    Usage:
      python3 -m skills.hitl approve <skill_id>
      python3 -m skills.hitl reject <skill_id>
      python3 -m skills.hitl list
    """
    if len(sys.argv) < 2:
        print("Usage: python3 -m skills.hitl <approve|reject|list> [skill_id]")
        sys.exit(1)

    command = sys.argv[1]
    store   = SkillStore()

    if command == "list":
        pending = store.load_by_status(PENDING_HITL)
        if not pending:
            print("No skills pending approval.")
        for s in pending:
            print(f"  {s.skill_id} | incident={s.incident_id} | {s.benchmark.summary()}")
        return

    if len(sys.argv) < 3:
        print(f"Usage: python3 -m skills.hitl {command} <skill_id>")
        sys.exit(1)

    skill_id = sys.argv[2]
    # Need Hermes client for orchestrator but not for approve/reject
    from agents.llm_client import make_hermes_client
    orchestrator = HITLOrchestrator(
        hermes=Hermes(client=make_hermes_client()),
        store=store,
    )

    if command == "approve":
        approved_by = sys.argv[3] if len(sys.argv) > 3 else "operator"
        success = orchestrator.approve(skill_id, approved_by=approved_by)
        sys.exit(0 if success else 1)

    elif command == "reject":
        success = orchestrator.reject(skill_id)
        sys.exit(0 if success else 1)

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
