# AES — OpenClaw Package
# Duc Vu owns this package.
#
# OpenClaw is the execution layer — it receives Hermes verdicts and acts on them.
# It does not reason or decide; it executes with precision.
#
# Duc's work (Milestones 1-4):
#
#   response_agent.py owns the signed firmware remediation pipeline for ESP32-CAM.
#                   Steps: checkout repo → isolate vulnerable module → pass to Hermes
#                   for patch → Gate 1 (Semgrep) → Gate 2 (Compile-Boot-Diff) →
#                   signed serial install → authenticated fresh-boot proof.
#                   NEVER skip Gate 1 or Gate 2. Failed patches go to outputs/patches/failed/.
#
#   solution2.py  — Gateway quarantine for closed-firmware devices.
#                   Steps: iptables --check dry-run ALWAYS FIRST → write block rule
#                   to Raspberry Pi gateway via SSH → verify traffic drops.
#                   NEVER write a live iptables rule without dry-run passing first.
#
#   gateway.py    — SSH client for the Raspberry Pi gateway.
#                   Used by solution2.py for iptables writes.
#
# Handlers return "resolved", "pending", or "failed" so validation/dry-run can
# never be confused with enforcement.
