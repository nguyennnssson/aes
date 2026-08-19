"""Add an independently reviewed sample to an authenticated benchmark corpus.

Usage:
  AES_BENCHMARK_HMAC_KEY=... python scripts/label_sample.py ATTACK sample.json attack_labels.jsonl
  AES_BENCHMARK_HMAC_KEY=... python scripts/label_sample.py NORMAL sample.json normal_labels.jsonl
"""

import argparse
import json
import math
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills.trusted_labels import sign_ground_truth


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("label", choices=("ATTACK", "NORMAL"))
    parser.add_argument("sample", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--reviewer", required=True)
    args = parser.parse_args()

    key = os.getenv("AES_BENCHMARK_HMAC_KEY", "")
    if len(key) < 32:
        raise SystemExit("AES_BENCHMARK_HMAC_KEY must contain at least 32 characters")
    sample = json.loads(args.sample.read_text(encoding="utf-8"))
    deviations = sample.get("deviations")
    if not isinstance(deviations, dict) or not deviations:
        raise SystemExit("sample must contain a non-empty deviations object")
    if not all(isinstance(value, (int, float)) and not isinstance(value, bool)
               and math.isfinite(float(value)) for value in deviations.values()):
        raise SystemExit("all deviations must be finite numbers")

    sample["sample_id"] = sample.get("sample_id") or sample.get("incident_id") or f"sample-{uuid.uuid4().hex}"
    sample["ground_truth"] = args.label
    sample["label_source"] = "operator-review"
    sample["label_reviewer"] = args.reviewer[:128]
    sample["label_at"] = datetime.now(timezone.utc).isoformat()
    sample["label_signature"] = sign_ground_truth(sample, args.label, key)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(sample, allow_nan=False) + "\n")
    print(f"labelled {sample['sample_id']} as {args.label} → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
