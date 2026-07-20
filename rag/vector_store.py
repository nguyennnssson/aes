"""
AES — ChromaDB Vector Store
============================
Single accessor for the CVE knowledge base collection.
All RAG components use get_collection() — no direct ChromaDB init elsewhere.

Collection: cve_knowledge_base
Space:      cosine similarity
Embeddings: nomic-embed-text via Ollama

chromadb is imported LAZILY (inside the functions) so that a missing chromadb
package degrades to a caught error inside IntelAgent.query() — which returns a
"proceed on anomaly alone" context — instead of crashing every module that
imports the monitor/intel path at startup.
"""

import os
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:                      # type-checking only — no runtime import
    import chromadb

COLLECTION_NAME = "cve_knowledge_base"
OLLAMA_URL      = "http://localhost:11434/api/embeddings"
EMBED_MODEL     = "nomic-embed-text"

# Module-level cache — only one client and collection per process
_client     = None
_collection = None


def _get_embedding_function():
    from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
    return OllamaEmbeddingFunction(
        model_name=EMBED_MODEL,
        url=OLLAMA_URL,
    )


def get_collection() -> "chromadb.Collection":
    """
    Returns the cve_knowledge_base ChromaDB collection.
    Initializes the client on first call, reuses it after. Raises (ImportError if
    chromadb is not installed, or a connection error) when the store/embedder is
    unavailable — callers in the incident path wrap this in try/except and degrade.
    """
    global _client, _collection
    if _collection is not None:
        return _collection

    import chromadb                    # lazy: absence degrades, doesn't crash importers

    persist_dir = os.getenv("CHROMA_PERSIST_DIR", "./aes_chromadb")
    _client = chromadb.PersistentClient(path=persist_dir)
    _collection = _client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=_get_embedding_function(),
        metadata={"hnsw:space": "cosine"},
    )
    return _collection
