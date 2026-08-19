# AES — RAG Package
# Retrieval-Augmented Generation pipeline for the CVE knowledge base.
#
# Files:
#   ingest_nvd.py     — NVD + Exploit-DB metadata + CISA + Espressif → local index.
#                        Run once to build the DB, then daily to refresh.
#   query_chromadb.py — compatibility query CLI for the local SQLite vector index.
#   vector_store.py   — embedded SQLite vectors + local Ollama embeddings.
#   embedder.py       — (Milestone 2, Son) nomic-embed-text wrapper with retry logic.
#   adapters/         — (Milestone 3, Son) Per-source ingestion adapters.
#
# Vector data lives at ./data/aes_intel.sqlite3 (gitignored; regenerate via ingest_nvd.py).
# Embedding model: nomic-embed-text via Ollama at localhost:11434.
