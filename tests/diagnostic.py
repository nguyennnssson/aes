"""AES — Mac Studio Diagnostic"""
import sys, os, shutil, subprocess

print("\n=== AES Mac Studio Diagnostic ===")
print(f"  Python                    {sys.version.split()[0]}")
print(f"  Mosquitto                 {shutil.which('mosquitto') or 'NOT FOUND'}")
print(f"  Ollama                    {shutil.which('ollama') or 'NOT FOUND'}")
print(f"  OPENAI_API_KEY            {'SET' if os.getenv('OPENAI_API_KEY') else 'NOT SET'}")
print(f"  codex CLI                 {shutil.which('codex') or 'NOT FOUND'}")

# ── Package checks (correct imports) ─────────────────────────────────────────
packages = {
    "paho-mqtt":  "paho.mqtt.client",
    "chromadb":   "chromadb",
    "openai":     "openai",
    "requests":   "requests",
    "ollama":     "ollama",
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

# ── ChromaDB document count ───────────────────────────────────────────────────
try:
    import chromadb
    from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
    nomic_ef = OllamaEmbeddingFunction(
        model_name="nomic-embed-text",
        url="http://localhost:11434/api/embeddings"
    )
    client = chromadb.PersistentClient(path="./aes_chromadb")
    col = client.get_or_create_collection(
        "cve_knowledge_base",
        embedding_function=nomic_ef,
        metadata={"hnsw:space": "cosine"}
    )
    print(f"  ChromaDB documents        {col.count()}")
except Exception as e:
    print(f"  ChromaDB documents        ERROR: {e}")

print("==================================\n")
