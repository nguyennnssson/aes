# AES — OpenClaw Package (Track 2 execution)
# Owner: Duc Vu.
#
# Gateway quarantine for closed-firmware devices. It receives a Hermes verdict
# from agents/response_agent.py and enforces it; it does not reason or decide.
# (The name is the team's label for the execution layer; this package does not
# use the external OpenClaw agent framework.)
#
#   solution2.py  — handle(): resolve the registry-pinned IP/MAC → verify the
#                   gateway's neighbor entry → dry run (always first) → enforce
#                   only when AES_FIREWALL_ENFORCE=1 → verify the DROP rules.
#                   Every decision is appended to outputs/firewall/actions.jsonl.
#                   `python -m openclaw.solution2 release <device_id>` rolls back.
#   firewall.py   — backends: iptables (locally or over SSH via GATEWAY_SSH),
#                   pf (macOS), netsh (Windows dev bench).
#
# Track 1 (signed firmware remediation) lives in agents/response_agent.py.
# Handlers return "resolved", "pending", or "failed" so validation/dry-run can
# never be confused with enforcement.
