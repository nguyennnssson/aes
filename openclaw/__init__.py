# AES — OpenClaw Package
# Duc Vu owns this package.
#
# OpenClaw is the execution layer — it receives Hermes verdicts and acts on them.
# It does not reason or decide; it executes with precision.
#
# Duc's work (Milestones 1-4):
#
#   solution1.py  — OTA patch pipeline for ESP32-CAM (open firmware).
#                   Steps: checkout repo → isolate vulnerable module → pass to Hermes
#                   for patch → Gate 1 (Semgrep) → Gate 2 (Compile-Boot-Diff) →
#                   esptool.py OTA push → dual-partition atomic switch → verify boot.
#                   NEVER skip Gate 1 or Gate 2. Failed patches go to outputs/patches/failed/.
#
#   solution2.py  — Network whitelist for closed-firmware devices (Tapo C200, etc.).
#                   Steps: iptables --check dry-run ALWAYS FIRST → write block rule
#                   to Raspberry Pi gateway via SSH → verify traffic drops.
#                   NEVER write a live iptables rule without dry-run passing first.
#
#   gateway.py    — SSH client for the Raspberry Pi gateway.
#                   Used by solution2.py for iptables writes.
#
# Interface contract with response_agent.py:
#   solution1.handle(incident, verdict) -> bool
#   solution2.handle(incident, verdict) -> bool
#   Both return True on success, False on failure (triggers retry in response_agent).
