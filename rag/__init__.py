# AES — RAG Package
# Retrieval-Augmented Generation pipeline for the CVE knowledge base.
#
# Files:
#   ingest_nvd.py     — NVD + Exploit-DB metadata + CISA KEV + Espressif → local index.
#                        Run once to build the index, then periodically to refresh.
#   query_index.py    — command-line query of the local SQLite vector index.
#   vector_store.py   — embedded SQLite vectors + local Ollama embeddings (used by
#                        ingestion and by agents/intel_agent.py).
#   embedder.py       — standalone nomic-embed-text helper with retries; the
#                        pipeline itself embeds through vector_store.py.
#
# Vector data lives at ./data/aes_intel.sqlite3 (gitignored; regenerate via ingest_nvd.py).
# Embedding model: nomic-embed-text via Ollama at localhost:11434.
