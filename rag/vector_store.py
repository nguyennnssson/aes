"""AES local CVE vector store.

This intentionally uses an embedded SQLite database instead of a network-capable
vector database server. Embeddings are produced by the local Ollama service and
stored as JSON vectors; cosine search happens in-process. The small, curated IoT
corpus does not need a remotely exposed database and therefore has no database
HTTP/RCE attack surface.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import threading
from pathlib import Path

import requests

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
_collection = None


def _validate_embedding(vector) -> list[float]:
    if not isinstance(vector, list) or not vector:
        raise ValueError("embedding service returned an empty vector")
    if len(vector) > 8192:
        raise ValueError("embedding exceeds the supported dimension limit")
    values = [float(value) for value in vector]
    if not all(math.isfinite(value) for value in values):
        raise ValueError("embedding contains non-finite values")
    return values


def _embed(texts: list[str]) -> list[list[float]]:
    """Use Ollama's current batch API, with a compatibility fallback."""
    if not texts or len(texts) > 64:
        raise ValueError("embedding batch must contain 1-64 texts")
    if any(not isinstance(text, str) or not text or len(text) > 16_384 for text in texts):
        raise ValueError("embedding text must contain 1-16384 characters")
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/embed",
            json={"model": EMBED_MODEL, "input": texts},
            timeout=60,
        )
        response.raise_for_status()
        vectors = response.json().get("embeddings")
        if isinstance(vectors, list) and len(vectors) == len(texts):
            return [_validate_embedding(vector) for vector in vectors]
    except (requests.RequestException, ValueError, TypeError):
        pass

    vectors = []
    for text in texts:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/embeddings",
            json={"model": EMBED_MODEL, "prompt": text},
            timeout=60,
        )
        response.raise_for_status()
        vectors.append(_validate_embedding(response.json().get("embedding")))
    return vectors


def _cosine_distance(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        return 2.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 2.0
    similarity = max(-1.0, min(1.0, dot / (left_norm * right_norm)))
    return 1.0 - similarity


class LocalVectorCollection:
    """Small compatibility surface used by the ingestion and Intel agents."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute(
                """CREATE TABLE IF NOT EXISTS documents (
                       id TEXT PRIMARY KEY,
                       document TEXT NOT NULL,
                       metadata TEXT NOT NULL,
                       embedding TEXT NOT NULL
                   )"""
            )

    def _connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def count(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM documents").fetchone()[0])

    def get(self, ids: list[str]) -> dict:
        if not ids:
            return {"ids": []}
        with self._connect() as db:
            found = [
                doc_id for doc_id in ids
                if db.execute(
                    "SELECT 1 FROM documents WHERE id = ?", (doc_id,)
                ).fetchone()
            ]
        return {"ids": found}

    def add(self, ids: list[str], documents: list[str], metadatas: list[dict]):
        if not (len(ids) == len(documents) == len(metadatas)):
            raise ValueError("ids, documents, and metadatas must have equal lengths")
        if any(not isinstance(doc_id, str) or not doc_id or len(doc_id) > 256 for doc_id in ids):
            raise ValueError("document ids must contain 1-256 characters")
        if any(not isinstance(metadata, dict) for metadata in metadatas):
            raise ValueError("metadata must be an object")
        encoded_metadata = [json.dumps(metadata, sort_keys=True, allow_nan=False) for metadata in metadatas]
        if any(len(item) > 16_384 for item in encoded_metadata):
            raise ValueError("metadata exceeds 16384 characters")
        vectors = _embed(documents)
        rows = [
            (doc_id, document, metadata, json.dumps(vector, allow_nan=False))
            for doc_id, document, metadata, vector in zip(ids, documents, encoded_metadata, vectors)
        ]
        with self._lock, self._connect() as db:
            db.executemany(
                "INSERT INTO documents(id, document, metadata, embedding) VALUES(?, ?, ?, ?)",
                rows,
            )

    def query(self, query_texts: list[str], n_results: int, include=None) -> dict:
        if not isinstance(n_results, int) or isinstance(n_results, bool):
            raise ValueError("n_results must be an integer")
        n_results = max(0, min(100, n_results))
        queries = _embed(query_texts)
        with self._connect() as db:
            rows = db.execute("SELECT id, document, metadata, embedding FROM documents").fetchall()
        result = {"ids": [], "documents": [], "metadatas": [], "distances": []}
        for query in queries:
            ranked = []
            for doc_id, document, metadata, embedding in rows:
                vector = _validate_embedding(json.loads(embedding))
                ranked.append((
                    _cosine_distance(query, vector), doc_id, document, json.loads(metadata)
                ))
            ranked.sort(key=lambda item: item[0])
            chosen = ranked[:n_results]
            result["distances"].append([item[0] for item in chosen])
            result["ids"].append([item[1] for item in chosen])
            result["documents"].append([item[2] for item in chosen])
            result["metadatas"].append([item[3] for item in chosen])
        return result


def get_collection() -> LocalVectorCollection:
    global _collection
    if _collection is None:
        configured = Path(os.getenv("AES_INTEL_DB", "./data/aes_intel.sqlite3"))
        _collection = LocalVectorCollection(configured.resolve())
    return _collection
