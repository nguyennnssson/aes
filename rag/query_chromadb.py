"""
AES — Intel Agent: Query the CVE Knowledge Base
Run this AFTER ingest_nvd.py has populated ChromaDB.

This is what fires during a real incident: takes an attack description,
searches ChromaDB for the most relevant CVEs, and returns them as context.
"""

import chromadb
from chromadb.utils.embedding_functions import OllamaEmbeddingFunction

CHROMA_PATH = "./aes_chromadb"

# Must match ingest_nvd.py exactly — same model, same URL
nomic_ef = OllamaEmbeddingFunction(
    model_name="nomic-embed-text",
    url="http://localhost:11434/api/embeddings",
)

# Connect to the same database ingest_nvd.py created
client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = client.get_or_create_collection(
    name="cve_knowledge_base",
    embedding_function=nomic_ef,
    metadata={"hnsw:space": "cosine"}
)


def query_intel(device_model: str, attack_signature: str, top_k: int = 10) -> str:
    """
    The Intel Agent's main function.

    Takes what we know about the attack and finds the most relevant CVEs.
    Returns a formatted string ready to paste into a the LLM prompt.

    Args:
        device_model:     e.g. "ESP32-CAM", "Hikvision DS-2CD2143G2-I"
        attack_signature: e.g. "CPU 85%, packet rate 10x normal, outbound TCP port 23"
        top_k:            how many CVEs to return (default 10, as per architecture)
    """
    # Build the search query from what we know about the attack
    query = f"{device_model} {attack_signature}"

    results = collection.query(
        query_texts=[query],
        n_results=min(top_k, collection.count()),  # can't query more than we have
        include=["documents", "metadatas", "distances"]
    )

    if not results["ids"][0]:
        return "No relevant CVEs found in knowledge base."

    # Format results for injection into the LLM's context
    lines = [
        f"INTEL REPORT — Top {len(results['ids'][0])} relevant CVEs",
        f"Query: {query}",
        "─" * 60,
    ]

    for i, (doc, meta, dist) in enumerate(zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0]
    )):
        # Distance is 0-2 in cosine space; convert to a 0-100 relevance score
        relevance = round((1 - dist / 2) * 100, 1)
        confidence = "HIGH" if relevance > 70 else "MEDIUM" if relevance > 50 else "LOW"

        lines.append(f"\n[{i+1}] {meta['cve_id']} | {meta['severity']} ({meta['score']}) | {meta['cwe']} | Relevance: {relevance}% [{confidence}]")
        lines.append(doc)

    return "\n".join(lines)


# ─── QUICK TEST ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"ChromaDB contains {collection.count()} CVE documents\n")

    # Simulate what happens when the Monitor Agent detects an attack on an ESP32
    result = query_intel(
        device_model="ESP32-CAM",
        attack_signature="CPU spike 85 percent, abnormal outbound connections, telnet port 23 traffic"
    )

    print(result)
