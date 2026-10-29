# AES — Tests Package
# All test and verification scripts live here.
#
# Files:
#   test_openai.py        — Smoke test for OpenAI API connectivity.
#                           Run this first after setting OPENAI_API_KEY.
#   (scripts/check_backends.py sends one live prompt through every configured
#    backend — Claude API, Claude Code CLI, OpenAI API, Codex CLI.)
#   test_hermes.py        — Unit tests for Hermes verdict hardening (action allowlist,
#                           confidence clamp, offline-fallback cap).
#   diagnostic.py         — environment health check: packages, services, local index count.
#                           Run this when setting up on a new machine.
#
# The rest of the unit suite (detection, diff-apply, sandbox, verify-log, Solution 1
# build) runs offline via `pytest tests/`.
