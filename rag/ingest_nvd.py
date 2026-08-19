"""
AES — RAG Ingestion Pipeline
Fetches IoT/camera security data from 4 sources and stores in the local AES
SQLite vector index.

Sources (per AES Overview):
  1. NVD      — Full CVE corpus with CVSS scores and CWE mapping
  2. Exploit-DB — catalogue metadata only (no exploit code is downloaded/executed)
  3. ICS-CERT — CISA advisories for IoT/OT-specific vulnerabilities
  4. Espressif — ESP32-specific security advisories from silicon vendor

Run once to build the database, then daily to keep it fresh.
"""

import csv
import io
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from rag.vector_store import get_collection


# ─── CONFIG ──────────────────────────────────────────────────────────────────

DAYS_BACK  = 365

# NVD keywords targeting our device surface
NVD_SEARCH_TERMS = [
    "ESP32",
    "IoT camera",
    "IP camera",
    "TP-Link Tapo",
    "firmware vulnerability",
    "MQTT",
]

NVD_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_CSV  = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
ICSCERT_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ─── LOCAL VECTOR INDEX ──────────────────────────────────────────────────────

collection = get_collection()


# ─── SHARED STORAGE ──────────────────────────────────────────────────────────

def store_document(doc_id: str, document_text: str, metadata: dict) -> bool:
    """Store a document in the local index. Returns True if new."""
    if collection.get(ids=[doc_id])["ids"]:
        return False
    collection.add(ids=[doc_id], documents=[document_text], metadatas=[metadata])
    return True


# ─── SOURCE 1: NVD ───────────────────────────────────────────────────────────

def ingest_nvd() -> tuple[int, int]:
    """Fetch CVEs from NVD REST API. Returns (stored, skipped)."""
    print("\n[NVD] Fetching CVEs...")
    stored = skipped = 0

    for term in NVD_SEARCH_TERMS:
        params = {
            "keywordSearch":  term,
            "resultsPerPage": 100,
        }
        try:
            r = requests.get(NVD_URL, params=params, timeout=30,
                             headers={"User-Agent": "AES-IngestPipeline/1.0"})
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            print(f"  '{term}' → {len(vulns)} CVEs")

            for v in vulns:
                parsed = _parse_nvd_cve(v)
                if parsed is None:
                    skipped += 1
                    continue
                doc_text = (
                    f"CVE ID: {parsed['cve_id']}\n"
                    f"Severity: {parsed['severity']} (Score: {parsed['score']})\n"
                    f"Weakness: {parsed['cwe']}\n"
                    f"Description: {parsed['description']}"
                )
                ok = store_document(parsed["cve_id"], doc_text, {
                    "cve_id":   parsed["cve_id"],
                    "severity": parsed["severity"],
                    "score":    str(parsed["score"]),
                    "cwe":      parsed["cwe"],
                    "published":parsed["published"],
                    "source":   "NVD",
                })
                stored += 1 if ok else 0
                skipped += 0 if ok else 1

        except requests.exceptions.RequestException as e:
            print(f"  ✗ Failed '{term}': {e}")

        time.sleep(6)  # NVD rate limit: 5 req/30s without API key

    return stored, skipped


def _parse_nvd_cve(vuln: dict) -> dict | None:
    try:
        cve        = vuln["cve"]
        cve_id     = cve["id"]
        descs      = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d["lang"] == "en"), None)
        if not description:
            return None

        severity = "UNKNOWN"; score = 0.0
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss     = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score    = cvss.get("baseScore", 0.0)
        elif "cvssMetricV2" in metrics:
            cvss  = metrics["cvssMetricV2"][0]["cvssData"]
            score = cvss.get("baseScore", 0.0)
            severity = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"

        cwe = "UNKNOWN"
        weaknesses = cve.get("weaknesses", [])
        if weaknesses:
            cwe_list = weaknesses[0].get("description", [])
            if cwe_list:
                cwe = cwe_list[0].get("value", "UNKNOWN")

        return {
            "cve_id": cve_id, "description": description,
            "severity": severity, "score": score,
            "cwe": cwe, "published": cve.get("published", ""),
        }
    except (KeyError, IndexError):
        return None


# ─── SOURCE 2: EXPLOIT-DB ────────────────────────────────────────────────────
# GitLab CSV export — no auth required.
# Filters for IoT/embedded platform entries relevant to our device surface.

EXPLOITDB_KEYWORDS = ["esp32", "iot", "camera", "mqtt", "firmware", "tapo", "router"]

def ingest_exploitdb() -> tuple[int, int]:
    """Fetch PoC exploits from Exploit-DB CSV. Returns (stored, skipped)."""
    print("\n[Exploit-DB] Fetching PoC exploits...")
    stored = skipped = 0

    try:
        r = requests.get(EXPLOITDB_CSV, timeout=60,
                         headers={"User-Agent": "AES-IngestPipeline/1.0"})
        r.raise_for_status()

        reader = csv.DictReader(io.StringIO(r.text))
        for row in reader:
            description = row.get("description", "").lower()
            platform    = row.get("platform", "").lower()

            # Filter: only keep entries relevant to our threat surface
            if not any(kw in description or kw in platform for kw in EXPLOITDB_KEYWORDS):
                skipped += 1
                continue

            edb_id   = f"EDB-{row.get('id', 'UNKNOWN')}"
            doc_text = (
                f"Exploit-DB ID: {edb_id}\n"
                f"Type: {row.get('type', 'unknown')} | Platform: {row.get('platform', 'unknown')}\n"
                f"Date: {row.get('date_published', '')}\n"
                f"CVE: {row.get('codes', 'N/A')}\n"
                f"Description: {row.get('description', '')}"
            )
            ok = store_document(edb_id, doc_text, {
                "cve_id":   row.get("codes", "N/A"),
                "severity": "UNKNOWN",
                "score":    "0.0",
                "cwe":      "UNKNOWN",
                "published":row.get("date_published", ""),
                "source":   "Exploit-DB",
            })
            stored += 1 if ok else 0
            skipped += 0 if ok else 1

        print(f"  → {stored} exploits stored, {skipped} skipped")

    except requests.exceptions.RequestException as e:
        print(f"  ✗ Failed to fetch Exploit-DB: {e}")

    return stored, skipped


# ─── SOURCE 3: ICS-CERT (CISA KEV) ──────────────────────────────────────────
# CISA Known Exploited Vulnerabilities catalog — JSON feed, no auth.
# IoT/OT specific vulnerabilities are our primary interest here.

ICSCERT_KEYWORDS = ["iot", "camera", "router", "firmware", "esp32", "mqtt",
                    "tapo", "hikvision", "reolink", "embedded"]

def ingest_icscert() -> tuple[int, int]:
    """Fetch CISA Known Exploited Vulnerabilities. Returns (stored, skipped)."""
    print("\n[ICS-CERT/CISA] Fetching known exploited vulnerabilities...")
    stored = skipped = 0

    try:
        r = requests.get(ICSCERT_URL, timeout=30,
                         headers={"User-Agent": "AES-IngestPipeline/1.0"})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        print(f"  → {len(vulns)} total CISA KEV entries, filtering for IoT surface...")

        for v in vulns:
            product = (v.get("product", "") + " " + v.get("vendorProject", "")).lower()
            desc    = v.get("shortDescription", "").lower()

            if not any(kw in product or kw in desc for kw in ICSCERT_KEYWORDS):
                skipped += 1
                continue

            cve_id   = v.get("cveID", f"CISA-{v.get('cveID', 'UNKNOWN')}")
            doc_text = (
                f"CVE ID: {cve_id}\n"
                f"Vendor: {v.get('vendorProject', 'unknown')} | Product: {v.get('product', 'unknown')}\n"
                f"Due Date: {v.get('dueDate', '')}\n"
                f"Required Action: {v.get('requiredAction', '')}\n"
                f"Description: {v.get('shortDescription', '')}"
            )
            ok = store_document(f"CISA-{cve_id}", doc_text, {
                "cve_id":   cve_id,
                "severity": "HIGH",    # CISA KEV = confirmed exploited = HIGH by definition
                "score":    "0.0",
                "cwe":      "UNKNOWN",
                "published":v.get("dateAdded", ""),
                "source":   "ICS-CERT",
            })
            stored += 1 if ok else 0
            skipped += 0 if ok else 1

        print(f"  → {stored} advisories stored")

    except requests.exceptions.RequestException as e:
        print(f"  ✗ Failed to fetch CISA KEV: {e}")

    return stored, skipped


# ─── SOURCE 4: ESPRESSIF ADVISORIES ──────────────────────────────────────────
# Espressif publishes ESP32-specific security advisories (the silicon-vendor source).
# Their advisory page is HTML with no public API, so we ingest a curated, version-
# controlled snapshot in espressif_advisories.json (built from
# docs.espressif.com/.../security/vulnerabilities.html). This gives the Intel Agent
# ESP32-specific intel — including OTA/secure-boot advisories — that generic NVD
# keyword search misses. Hermes-generated ESP32 patches are reasoned against this
# vendor guidance. To refresh: re-scrape that page into the JSON.

ESPRESSIF_ADVISORIES_PATH = Path(__file__).parent / "espressif_advisories.json"


def ingest_espressif() -> tuple[int, int]:
    """Ingest curated Espressif ESP32/ESP-IDF advisories. Returns (stored, skipped)."""
    print("\n[Espressif] Ingesting curated ESP32/ESP-IDF advisories...")
    stored = skipped = 0

    if not ESPRESSIF_ADVISORIES_PATH.exists():
        print(f"  ✗ {ESPRESSIF_ADVISORIES_PATH.name} not found — skipping Espressif source")
        return 0, 0

    try:
        data       = json.loads(ESPRESSIF_ADVISORIES_PATH.read_text(encoding="utf-8"))
        advisories = data.get("advisories", [])
    except (json.JSONDecodeError, OSError) as e:
        print(f"  ✗ Could not read advisories file: {e}")
        return 0, 0

    print(f"  → {len(advisories)} advisories in corpus")
    for adv in advisories:
        cve_id = adv.get("cve_id")
        if not cve_id:
            skipped += 1
            continue
        doc_text = (
            f"CVE ID: {cve_id}\n"
            f"Severity: {adv.get('severity', 'UNKNOWN')}\n"
            f"Weakness: {adv.get('cwe', 'UNKNOWN')}\n"
            f"Affected: {adv.get('affected', 'ESP-IDF')}\n"
            f"Title: {adv.get('title', '')}\n"
            f"Description: {adv.get('description', '')}\n"
            f"Resolution: {adv.get('resolution', '')}\n"
            f"Espressif Advisory: {adv.get('advisory', 'N/A')} ({adv.get('advisory_url', '')})"
        )
        # Namespace the id (ESP-) so the vendor advisory coexists with any NVD entry
        # for the same CVE instead of one silently deduping the other.
        ok = store_document(f"ESP-{cve_id}", doc_text, {
            "cve_id":    cve_id,
            "severity":  adv.get("severity", "UNKNOWN"),
            "score":     "N/A",
            "cwe":       adv.get("cwe", "UNKNOWN"),
            "published": adv.get("published", ""),
            "source":    "Espressif",
        })
        stored  += 1 if ok else 0
        skipped += 0 if ok else 1

    print(f"  → {stored} advisories stored, {skipped} skipped (duplicates/invalid)")
    return stored, skipped


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("AES — RAG Ingestion Pipeline")
    print(f"Sources: NVD | Exploit-DB | ICS-CERT | Espressif")
    print(f"DB before: {collection.count()} documents")
    print("=" * 60)

    total_stored = total_skipped = 0

    for ingest_fn in [ingest_nvd, ingest_exploitdb, ingest_icscert, ingest_espressif]:
        s, k = ingest_fn()
        total_stored  += s
        total_skipped += k

    print()
    print("=" * 60)
    print("Done.")
    print(f"  Stored  : {total_stored}  ← new entries added to the local vector index")
    print(f"  Skipped : {total_skipped}  ← duplicates, filtered, or no description")
    print(f"  DB total: {collection.count()} documents")
    print("=" * 60)


if __name__ == "__main__":
    main()
