# AES Config

## device_registry.json

Single source of truth for the device fleet. Every component loads from this file.

**To add a new device:** edit this file only. No Python changes needed.

```json
{
  "device-id": {
    "model":          "Hardware model name",
    "solution_track": 1,         // 1 = OTA patch (open firmware), 2 = whitelist (closed firmware)
    "owner":          "Vy",      // Who is responsible for this device
    "firmware":       "open",    // "open" = ESP-IDF patchable, "closed" = whitelist only
    "status":         "live",    // "live" = active, "bench-ready" = hardware present but not deployed
    "notes":          "..."
  }
}
```

**Solution tracks:**
- Track 1: ESP32-CAM and any other open-firmware device where we control the source code.
- Track 2: Tapo C200, Hikvision, Reolink, and any closed-firmware device. Hikvision/Reolink are one-config-file extensions — same pipeline, new whitelist source.

## .env (not committed)

Copy `.env.example` to `.env` and fill in your keys. Never commit `.env`.

Required keys: see `.env.example` at repo root.
