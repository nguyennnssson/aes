"""
AES — Embedder
==============
Wraps Ollama nomic-embed-text with retry logic.
Used by the ingestion pipeline and Intel Agent.

Returns 768-dimensional float vectors.
"""

import time
import requests

OLLAMA_URL  = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"


def nomic_embed(texts: list[str], retries: int = 3, timeout: int = 30) -> list[list[float]]:
    """
    Embed a list of texts using nomic-embed-text via Ollama.
    Retries with exponential backoff on failure.

    Args:
        texts:   List of strings to embed.
        retries: Number of attempts before raising.
        timeout: HTTP timeout per request in seconds.

    Returns:
        List of 768-dim float vectors, one per input text.

    Raises:
        RuntimeError: If all retry attempts fail.
    """
    embeddings = []
    for text in texts:
        for attempt in range(retries):
            try:
                r = requests.post(
                    OLLAMA_URL,
                    json={"model": EMBED_MODEL, "prompt": text},
                    timeout=timeout,
                )
                r.raise_for_status()
                embeddings.append(r.json()["embedding"])
                break
            except (requests.RequestException, KeyError) as e:
                if attempt == retries - 1:
                    raise RuntimeError(
                        f"Embedding failed after {retries} attempts: {e}"
                    )
                time.sleep(2 ** attempt)   # 1s, 2s, 4s backoff
    return embeddings
