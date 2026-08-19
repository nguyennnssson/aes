"""
AES — Skill Injector
=====================
Owner: Son Nguyen (AI Infra)

Deploys an APPROVED skill (a set of EWMA detection params) by writing it to
config/active_detection.json. The live monitor process polls that file's mtime
and adopts the new params on its next reading — no restart, no importlib.reload,
no cross-process module surgery (audit findings C1, C2).

HOW IT WORKS:
  1. Back up current active_detection.json → previous_detection.json
  2. Atomically write skill.params to active_detection.json (tmp + os.replace)
  3. Mark skill INJECTED in the store

SAFETY:
  - Only APPROVED skills can be injected (status check enforced)
  - Atomic replace — a crash mid-write can never leave a half-written params file
  - On any error, rolls back to previous_detection.json automatically

Usage:
    from skills.inject import Injector
    from skills.store import SkillStore

    store = SkillStore()
    injector = Injector(store)
    injector.inject(skill)
"""

import json
import os
import shutil
from pathlib import Path

from skills.schema import Skill, APPROVED
from skills.store import SkillStore

_CONFIG_DIR = Path(__file__).parent.parent / "config"
_ACTIVE     = _CONFIG_DIR / "active_detection.json"
_PREVIOUS   = _CONFIG_DIR / "previous_detection.json"


class Injector:

    def __init__(self, store: SkillStore = None):
        self.store = store

    def inject(self, skill: Skill) -> bool:
        """
        Deploy an approved skill's params live. Returns True on success,
        False on failure (auto-rollback attempted). Only APPROVED skills accepted.
        """
        if skill.status != APPROVED:
            print(f"[INJECT] Refused — skill {skill.skill_id} is {skill.status}, not APPROVED")
            return False

        if not skill.approval_is_valid():
            print(f"[INJECT] Refused — skill {skill.skill_id} approval signature is missing or invalid")
            return False

        from agents.monitor_agent import validate_detection_params
        validated = validate_detection_params(skill.params)
        if not validated or set(validated) != set(skill.params):
            print(f"[INJECT] Refused — skill {skill.skill_id} has no valid params")
            return False
        skill.params = validated

        print(f"[INJECT] Injecting skill {skill.skill_id} (v{skill.version}) params={skill.params}")

        self._backup_current()
        try:
            self._atomic_write(_ACTIVE, skill.params)
            print(f"[INJECT] Wrote active params to {_ACTIVE}")

            skill.mark_injected()
            if self.store:
                self.store.save(skill)

            print(f"[INJECT] ✅ Skill {skill.skill_id} is now live (monitor picks it up next reading)")
            return True
        except Exception as e:
            print(f"[INJECT] ❌ Injection failed: {e} — rolling back")
            self._rollback()
            return False

    def rollback(self, skill: Skill) -> bool:
        """Manually roll back to the previous params."""
        print(f"[INJECT] Rolling back from skill {skill.skill_id}...")
        return self._rollback()

    # ─── PRIVATE ─────────────────────────────────────────────────────────────

    def _atomic_write(self, path: Path, params: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(params, indent=2))
        os.replace(tmp, path)   # atomic on the same filesystem

    def _backup_current(self):
        if _ACTIVE.exists():
            shutil.copy(_ACTIVE, _PREVIOUS)
            print(f"[INJECT] Backed up current params to {_PREVIOUS}")

    def _rollback(self) -> bool:
        if not _PREVIOUS.exists():
            print("[INJECT] No previous params to roll back to")
            return False
        try:
            shutil.copy(_PREVIOUS, _ACTIVE)
            print("[INJECT] ✅ Rolled back to previous params")
            return True
        except Exception as e:
            print(f"[INJECT] Rollback failed: {e}")
            return False
