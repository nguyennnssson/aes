"""HMAC-authenticated ground-truth labels shared by training and deployment gates."""

import hashlib
import hmac
import json
import math
import os


def _payload(sample: dict, ground_truth: str) -> bytes:
    deviations = sample.get("deviations")
    if not isinstance(deviations, dict) or not deviations:
        raise ValueError("deviations must be a non-empty object")
    if not all(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        for value in deviations.values()
    ):
        raise ValueError("deviations must contain only finite numbers")
    sample_id = sample.get("sample_id") or sample.get("incident_id")
    if not isinstance(sample_id, str) or not sample_id:
        raise ValueError("sample_id is required")
    return json.dumps(
        {"sample_id": sample_id, "ground_truth": ground_truth, "deviations": deviations},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sign_ground_truth(sample: dict, ground_truth: str, key: str | None = None) -> str:
    key = key if key is not None else os.getenv("AES_BENCHMARK_HMAC_KEY", "")
    if len(key) < 32:
        raise ValueError("AES_BENCHMARK_HMAC_KEY must contain at least 32 characters")
    if ground_truth not in {"ATTACK", "NORMAL"}:
        raise ValueError("ground_truth must be ATTACK or NORMAL")
    return hmac.new(key.encode("utf-8"), _payload(sample, ground_truth), hashlib.sha256).hexdigest()


def verify_ground_truth(sample: dict, expected: str, key: str | None = None) -> bool:
    key = key if key is not None else os.getenv("AES_BENCHMARK_HMAC_KEY", "")
    signature = sample.get("label_signature")
    if len(key) < 32 or sample.get("ground_truth") != expected or not isinstance(signature, str):
        return False
    try:
        calculated = sign_ground_truth(sample, expected, key)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(signature, calculated)
