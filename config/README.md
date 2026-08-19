# AES Config

## device_registry.json

Single source of truth for the device fleet. Every component loads from this file.

**To add a new device:** edit this file only. No Python changes needed.

```json
{
  "device-id": {
    "model":          "Hardware model name",
    "solution_track": 1,         // 1 = signed firmware remediation, 2 = quarantine
    "owner":          "Vy",      // Who is responsible for this device
    "firmware":       "open",    // "open" = ESP-IDF patchable, "closed" = whitelist only
    "status":         "live",    // "live" = active, "bench-ready" = hardware present but not deployed
    "ip":             "192.168.4.20", // required for track 2; static DHCP lease
    "mac":            "aa:bb:cc:dd:ee:ff", // required for track 2 identity check
    "notes":          "..."
  }
}
```

**Solution tracks:**
- Track 1: open firmware where the operator controls source, signing keys, and secure-boot provisioning.
- Track 2: closed firmware quarantined at the forwarding gateway. The registry IP/MAC must match a static dnsmasq lease; AES verifies the gateway neighbor entry before applying bidirectional DROP rules.

## .env (not committed)

Copy `.env.example` to `.env` and fill in your keys. Never commit `.env`.

Required keys: see `.env.example` at repo root.
