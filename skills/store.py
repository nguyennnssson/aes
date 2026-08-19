"""
AES — Skill Store
==================
Owner: Son Nguyen (AI Infra)

Persists skills to disk as JSONL (one JSON object per line).
Each skill is appended on save — full history is preserved.
Latest version of each skill_id is returned on load.

File: config/skills.jsonl  (gitignored — runtime state)

Usage:
    from skills.store import SkillStore
    from skills.schema import Skill

    store = SkillStore()
    store.save(skill)
    all_skills  = store.load_all()
    latest      = store.load_latest(skill_id)
    pending     = store.load_by_status("PENDING_HITL")
"""

import json
import os
import threading
from pathlib import Path
from typing import Optional

from skills.schema import Skill

_DEFAULT_PATH = Path(__file__).parent.parent / "config" / "skills.jsonl"
_STORE_LOCK = threading.Lock()


class SkillStore:

    def __init__(self, path: Path = _DEFAULT_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ─── WRITE ───────────────────────────────────────────────────────────────

    def save(self, skill: Skill) -> None:
        """Append skill to JSONL store. Preserves full history."""
        with _STORE_LOCK, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(skill.to_dict(), allow_nan=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

    # ─── READ ────────────────────────────────────────────────────────────────

    def load_all(self) -> list[Skill]:
        """Load every skill record (all versions, all statuses)."""
        if not self.path.exists():
            return []
        skills = []
        with _STORE_LOCK, self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        skills.append(Skill.from_dict(json.loads(line)))
                    except Exception as e:
                        print(f"[STORE] Skipping malformed record: {e}")
        return skills

    def load_latest(self, skill_id: str) -> Optional[Skill]:
        """Return the most recently saved record for a given skill_id."""
        matches = [s for s in self.load_all() if s.skill_id == skill_id]
        return matches[-1] if matches else None

    def load_by_status(self, status: str) -> list[Skill]:
        """
        Return the latest record of each skill_id that has the given status.
        Uses latest-per-skill semantics — historical records are ignored.
        """
        # Build a map: skill_id → latest record
        latest: dict[str, Skill] = {}
        for s in self.load_all():
            latest[s.skill_id] = s   # later entries overwrite earlier ones
        return [s for s in latest.values() if s.status == status]

    def load_injected(self) -> list[Skill]:
        """Return all live injected skills."""
        return self.load_by_status("INJECTED")

    # ─── HELPERS ─────────────────────────────────────────────────────────────

    def count(self) -> int:
        return len(self.load_all())
