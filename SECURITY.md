# Security Policy

AES is a security project, so we take vulnerabilities in AES itself seriously.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue, affected component, and steps to reproduce.

We aim to acknowledge reports within a few days and will keep you updated on
remediation. Once a fix is available, we'll coordinate disclosure with you.

## Scope

In scope:

- The Python pipeline (`agents/`, `openclaw/`, `gates/`, `rag/`, `skills/`).
- The ESP32-CAM firmware (`esp32-cam/`).
- The dashboard and web app (`dashboard/`, `web/`).
- Handling of secrets, device credentials, and the model prompt/injection surface
  (retrieved CVE context is treated as untrusted — see `agents/hermes.py`).

Out of scope:

- Third-party dependencies (report those upstream).
- Issues that require an already-compromised host or physical device access.
- The intentionally-vulnerable demo firmware (`esp32-cam/main/main_vulnerable.c`),
  which exists to exercise the detection/patch pipeline.

## Handling notes for operators

- Physical actions (firmware flash, firewall enforcement) are opt-in behind
  environment flags and default to non-destructive dry-run / hold-for-approval.
- The dashboard controls live detection and must never be exposed to the public
  internet — bind it to localhost or a trusted LAN only.
- Never commit `.env`, API keys, webhooks, or device credentials.
