"""
AES — Intel Agent
=================
Owner: Son Nguyen (AI Infra)

Queries the CVE knowledge base for the most relevant context
given a device model, firmware version, and attack signature.
Fires concurrently with Hermes analysis on every confirmed anomaly.

Usage:
    from agents.intel_agent import IntelAgent
    agent = IntelAgent()
    ctx = agent.query("ESP32-CAM", "1.0.0", "CPU spike + outbound TCP 23")
    print(ctx.formatted)   # inject into Hermes prompt
"""

from dataclasses import dataclass, field
import math
import os
from rag.vector_store import get_collection


@dataclass
class IntelContext:
    query:     str
    chunks:    list[dict] = field(default_factory=list)
    formatted: str = ""


class IntelAgent:

    def query(
        self,
        device_model:     str,
        firmware_version: str,
        attack_signature: str,
        top_k:            int = 5,
    ) -> IntelContext:
        """
        Query the CVE knowledge base.

        Args:
            device_model:     e.g. "ESP32-CAM"
            firmware_version: e.g. "1.0.0" — narrows results to device-specific CVEs
            attack_signature: e.g. "CPU spike + outbound TCP 23"
            top_k:            max chunks to return (default 10 per architecture spec)

        Returns:
            IntelContext with formatted string ready to inject into Hermes prompt.
        """
        q = f"{device_model} {firmware_version} {attack_signature}"[:2000]

        # The embedded vector index query depends on a live Ollama embedder.
        # If either is unreachable, degrade gracefully — Hermes can still reason
        # from the anomaly alone. NEVER raise into the incident pipeline (H2):
        # an exception here would otherwise crash on_message and strand the device.
        try:
            collection = get_collection()
            count = collection.count()

            if count == 0:
                return IntelContext(query=q, formatted="Knowledge base is empty — run ingest first.")

            results = collection.query(
                query_texts=[q],
                n_results=min(max(1, top_k * 3), count),
                include=["documents", "metadatas", "distances"],
                # NOTE: confidence filter requires re-ingestion with confidence metadata field.
                # Current data (NVD/Exploit-DB/ICS-CERT) does not include this field yet.
                # where={"confidence": {"$gt": 0.7}},
            )
        except Exception as e:
            print(f"[INTEL] Query failed ({e}) — returning degraded context")
            return IntelContext(
                query=q,
                formatted=f"INTEL UNAVAILABLE — vector store/embedder unreachable ({e}). "
                          f"Proceed on anomaly signature alone.",
            )

        try:
            min_relevance = float(os.getenv("INTEL_MIN_RELEVANCE", "0.65"))
        except ValueError:
            min_relevance = 0.65
        if not math.isfinite(min_relevance):
            min_relevance = 0.65
        min_relevance = max(0.0, min(1.0, min_relevance))
        allowed_sources = {"NVD", "Exploit-DB", "ICS-CERT", "Espressif"}
        chunks = []
        if results["ids"][0]:
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            ):
                relevance = 1.0 - float(dist)
                if (math.isfinite(relevance) and relevance >= min_relevance
                        and meta.get("source") in allowed_sources):
                    chunks.append({"doc": str(doc)[:4000], "meta": meta, "dist": float(dist)})
                if len(chunks) >= top_k:
                    break

        return IntelContext(
            query=q,
            chunks=chunks,
            formatted=format_context(q, chunks),
        )


def format_context(query: str, chunks: list[dict]) -> str:
    """
    Formats CVE chunks for injection into Hermes prompt.
    Header uses metadata the ingest pipeline actually stores (severity + CVSS
    score). The old 'Confidence' field was never populated and always rendered
    '?' (audit finding M2).
    [Source: {source} | CVE: {cve_id} | Severity: {severity} ({score})] {chunk_text}
    Separated by \\n---\\n
    """
    if not chunks:
        return "No relevant CVEs found in knowledge base."

    lines = [
        f"INTEL REPORT — Top {len(chunks)} relevant CVEs",
        f"Query: {query}",
        "─" * 60,
    ]

    for i, c in enumerate(chunks):
        meta      = c["meta"]
        relevance = round((1 - c["dist"]) * 100, 1)
        header    = (
            f"\n[{i+1}] [Source: {meta.get('source', '?')} | "
            f"CVE: {meta.get('cve_id', '?')} | "
            f"Severity: {meta.get('severity', '?')} ({meta.get('score', '?')})] "
            f"Relevance: {relevance}%"
        )
        lines.append(header)
        lines.append(c["doc"])
        lines.append("---")

    return "\n".join(lines)
