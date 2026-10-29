# Vulnerability index

How the CVE context Hermes receives is built.

```bash
ollama pull nomic-embed-text
python -m rag.ingest_nvd
```

`rag/ingest_nvd.py` builds an embedded SQLite vector index at
`AES_INTEL_DB` (default `./data/aes_intel.sqlite3`). It uses `nomic-embed-text`
embeddings from a local Ollama server and cosine similarity. The index is not
committed; each machine builds its own. Sources:

| Source | What is ingested | Limit in the code |
|---|---|---|
| NVD CVE API 2.0 | CVE description, CVSS, CWE | first 100 results for each of 6 keyword searches (≤ 600) |
| Exploit-DB `files_exploits.csv` | catalogue metadata only, no exploit code | rows matching 7 IoT keywords |
| CISA Known Exploited Vulnerabilities | KEV entries matching IoT keywords | stored with the source label `ICS-CERT` |
| Espressif advisories | curated snapshot in `rag/espressif_advisories.json` | 16 advisories |

Records are de-duplicated by ID. The total depends on what the live feeds
return on the day of ingestion, and the script prints `DB total` when it
finishes. Only chunks with relevance ≥ `INTEL_MIN_RELEVANCE` (default 0.65) are
sent to Hermes, inside a fenced block marked as untrusted data.

[← Back to README](../README.md)
