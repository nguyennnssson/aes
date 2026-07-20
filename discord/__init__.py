# AES — Discord Package
# All Discord communication lives here.
#
# Files:
#   discord_alerts.py — Webhook-based alert posting to #aes-alerts.
#                        Fires automatically on every detected anomaly.
#                        Also posts Hermes learning update proposals for HITL ✅ approval.
#
# NOTE: If you install discord.py (for the reaction-watcher bot), import it as
#       'import discord as discord_lib' to avoid shadowing this package.
#
# Duc's work (Milestone 4):
#   discord_bot.py  — Bot token-based client that watches for ✅ reactions
#                     on skill-rewrite proposals and triggers hot injection.
#   slash_commands.py — /aes status command returning live fleet state.
#
# Required env vars:
#   DISCORD_WEBHOOK_URL     — For discord_alerts.py (webhook, no bot token needed)
#   DISCORD_BOT_TOKEN       — For discord_bot.py (Duc's bot, separate from webhook)
#   DISCORD_ALERT_CHANNEL_ID — Channel ID for #aes-alerts
