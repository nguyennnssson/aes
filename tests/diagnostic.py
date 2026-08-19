"""AES environment diagnostic (Windows, Linux, or macOS)."""
import sys, os, shutil, subprocess

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

print("\n=== AES Mac Studio Diagnostic ===")
print(f"  Python                    {sys.version.split()[0]}")
print(f"  Mosquitto                 {shutil.which('mosquitto') or 'NOT FOUND'}")
print(f"  Ollama                    {shutil.which('ollama') or 'NOT FOUND'}")
print(f"  OPENAI_API_KEY            {'SET' if os.getenv('OPENAI_API_KEY') else 'NOT SET'}")
print(f"  codex CLI                 {shutil.which('codex') or 'NOT FOUND'}")

# ── Package checks (correct imports) ─────────────────────────────────────────
packages = {
    "paho-mqtt":  "paho.mqtt.client",
    "openai":     "openai",
    "requests":   "requests",
    "fastapi":    "fastapi",
}
for name, module in packages.items():
    try:
        __import__(module)
        print(f"  pip: {name:<20} ✅ installed")
    except ImportError as e:
        print(f"  pip: {name:<20} ❌ missing ({e})")

# ── Ollama models ─────────────────────────────────────────────────────────────
try:
    r = subprocess.run(["ollama", "list"], capture_output=True, text=True)
    models = r.stdout.strip()
    print(f"  Ollama models             {models.splitlines()[1] if len(models.splitlines()) > 1 else 'none'}")
except Exception:
    print("  Ollama models             ollama not found")

# ── Mosquitto running ─────────────────────────────────────────────────────────
try:
    r = subprocess.run(["pgrep", "-x", "mosquitto"], capture_output=True, text=True)
    print(f"  Mosquitto running         {'YES' if r.stdout.strip() else 'NO'}")
except Exception:
    print("  Mosquitto running         unknown")

# ── Local Intel index document count ──────────────────────────────────────────
try:
    from rag.vector_store import get_collection
    print(f"  Intel index documents     {get_collection().count()}")
except Exception as e:
    print(f"  Intel index documents     ERROR: {e}")

secure_mqtt = bool(os.getenv("MQTT_CA_CERT") and
                   (os.getenv("MQTT_MONITOR_USERNAME") or os.getenv("MQTT_USERNAME")))
print(f"  Secure MQTT config        {'SET' if secure_mqtt else 'NOT SET'}")
print(f"  Dashboard token           {'SET' if os.getenv('AES_DASHBOARD_TOKEN') else 'NOT SET'}")
print(f"  Audit HMAC key            {'SET' if os.getenv('AES_AUDIT_HMAC_KEY') else 'NOT SET'}")

print("==================================\n")
