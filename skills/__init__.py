# AES — Skills Package (Milestone 7 — DONE)
# Hermes-generated detection skills — Solution 3, the self-rewriting detection system.
#
# Files:
#   schema.py   — Skill dataclass: identity, provenance, detection code, benchmark, approval status
#   store.py    — JSONL persistence, latest-per-skill semantics
#   sandbox.py  — Replay benchmark against historical incidents before deploy
#   inject.py   — Hot-inject approved skill via importlib.reload, auto-rollback on failure
#   hitl.py     — Full orchestrator: propose → sandbox → Discord → approve → inject
#
# Runtime files (gitignored):
#   active_skill.py   — Currently deployed detection rule
#   previous_skill.py — Previous rule (rollback target)
