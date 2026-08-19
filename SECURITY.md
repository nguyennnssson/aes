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

- Firmware installation requires strict gate evidence, a signed binary, secure-
  boot/flash-encryption attestation, and an HMAC approval bound to the artifact
  hashes. Firewall dry runs never resolve an incident.
- MQTT uses TLS, per-device credentials, registry enrollment, and broker topic
  ACLs. `AES_INSECURE_DEV_MQTT=1` is for isolated loopback tests only.
- Every dashboard API requires `AES_DASHBOARD_TOKEN`. Keep it on localhost; use a
  TLS reverse proxy plus explicit host/origin allowlists for any trusted-LAN use.
- Production requires HMAC keys for the incident audit chain, firmware approvals,
  skill approvals, and benchmark labels.
- Never commit `.env`, API keys, webhooks, or device credentials.
