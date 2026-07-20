"""
AES — ChromaDB Vector Store
============================
Single accessor for the CVE knowledge base collection.
All RAG components use get_collection() — no direct ChromaDB init elsewhere.

Collection: cve_knowledge_base
Space:      cosine similarity
Embeddings: nomic-embed-text via Ollama
"""

import os
from typing import Optional
import chromadb
from chromadb.utils.embedding_functions import OllamaEmbeddingFunction

COLLECTION_NAME = "cve_knowledge_base"
OLLAMA_URL      = "http://localhost:11434/api/embeddings"
EMBED_MODEL     = "nomic-embed-text"

# Module-level cache — only one client and collection per process
_client:     Optional[chromadb.Client]     = None
_collection: Optional[chromadb.Collection] = None


def _get_embedding_function() -> OllamaEmbeddingFunction:
    return OllamaEmbeddingFunction(
        model_name=EMBED_MODEL,
        url=OLLAMA_URL,
    )


def get_collection() -> chromadb.Collection:
    """
    Returns the aes_intel ChromaDB collection.
    Initializes the client on first call, reuses it after.
    """
    global _client, _collection
    if _collection is not None:
        return _collection

    persist_dir = os.getenv("CHROMA_PERSIST_DIR", "./aes_chromadb")
    _client = chromadb.PersistentClient(path=persist_dir)
    _collection = _client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=_get_embedding_function(),
        metadata={"hnsw:space": "cosine"},
    )
    return _collection
