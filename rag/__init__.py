# AES — RAG Package
# Retrieval-Augmented Generation pipeline for the CVE knowledge base.
#
# Files:
#   ingest_nvd.py     — Ingestion pipeline: NVD + Exploit-DB + ICS-CERT + Espressif → ChromaDB.
#                        Run once to build the DB, then daily to refresh.
#   query_chromadb.py — Intel Agent query layer. Called during every incident.
#   vector_store.py   — (Milestone 2, Son) ChromaDB abstraction with typed metadata schema.
#   embedder.py       — (Milestone 2, Son) nomic-embed-text wrapper with retry logic.
#   adapters/         — (Milestone 3, Son) Per-source ingestion adapters.
#
# ChromaDB data lives at ./aes_chromadb/ (gitignored, regenerate via ingest_nvd.py).
# Embedding model: nomic-embed-text via Ollama at localhost:11434.
