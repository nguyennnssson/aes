"""
AES — Skill Sandbox
====================
Owner: Son Nguyen (AI Infra)

Benchmarks a proposed skill (a set of EWMA detection params) against historical
data before it goes to HITL Discord approval.

HOW IT WORKS:
  1. Load historical ATTACK incidents from aes_incidents.jsonl
  2. Load sampled NORMAL readings from aes_normals.jsonl
  3. Replay each through the proposed params using the SAME evaluate_detection()
     the live monitor uses (no exec, no code execution at all)
  4. Measure detection_rate (attacks flagged) and false_positive_rate (normals flagged)

Why params, not code: the learning loop tunes EWMA thresholds. There is no
model-written code to execute, so the sandbox is pure arithmetic — safe and fast.

Thresholds (configurable):
  MIN_DETECTION_RATE  = 0.80   (must catch 80%+ of replayed attacks)
  MAX_FALSE_POSITIVE  = 0.10   (must not flag 10%+ of normal traffic)

Usage:
    from skills.sandbox import Sandbox
    from skills.schema import Skill

    result = Sandbox().benchmark(skill)
    if result.passed():
        # proceed to HITL Discord approval
"""

import json
import time
from pathlib import Path

from agents.monitor_agent import evaluate_detection
from skills.schema import Skill, BenchmarkResult

_INCIDENTS_PATH = Path(__file__).parent.parent / "aes_incidents.jsonl"
_NORMALS_PATH   = Path(__file__).parent.parent / "aes_normals.jsonl"

# Deployment thresholds
MIN_DETECTION_RATE = 0.80
MAX_FALSE_POSITIVE = 0.10


class Sandbox:

    def __init__(self, incidents_path: Path = _INCIDENTS_PATH, normals_path: Path = _NORMALS_PATH):
        self.incidents_path = incidents_path
        self.normals_path   = normals_path

    def benchmark(self, skill: Skill) -> BenchmarkResult:
        """
        Replay historical attacks + normals through the proposed params.
        Populates and returns a BenchmarkResult. Also updates skill.benchmark.
        """
        print(f"[SANDBOX] Benchmarking {skill.skill_id} with params={skill.params}...")

        # Attacks: every logged incident is a confirmed anomaly. Exclude fabricated
        # demo incidents (stamped "demo": true by scripts/live_demo.py) so staged
        # theater data doesn't contaminate the real detection-rate measurement
        # (REVIEW P1-6). NOTE: detection_rate here is measured over PREVIOUSLY
        # DETECTED incidents only, so it proves "no regression," not "catches what
        # we previously missed" — the stealth before/after demo is the evidence for
        # the latter (a missed attack cannot appear in this corpus by construction).
        all_incidents = self._load_jsonl(self.incidents_path)
        attacks = [a for a in all_incidents if not a.get("demo")]
        excluded = len(all_incidents) - len(attacks)
        if excluded:
            print(f"[SANDBOX] Excluded {excluded} demo incident(s) from the attack corpus")
        # Normals: sampled NORMAL readings (status guard keeps this honest if the
        # files ever share a path).
        normals = [n for n in self._load_jsonl(self.normals_path) if n.get("status") == "NORMAL"]

        print(f"[SANDBOX] {len(attacks)} attack incidents, {len(normals)} normal readings")
        if not normals:
            # Without normals the FP gate cannot fail — refuse to certify a skill
            # on attack-only data rather than rubber-stamp it (audit finding C4).
            print("[SANDBOX] ⚠ No normal readings yet — run the simulator in normal mode "
                  "to build a false-positive corpus before approving skills.")

        start = time.perf_counter()
        detection_rate = self._flag_rate(attacks, skill.params)
        false_positive = self._flag_rate(normals, skill.params)
        latency_ms     = round((time.perf_counter() - start) * 1000, 3)

        result = BenchmarkResult(
            detection_rate      = detection_rate,
            false_positive_rate = false_positive,
            latency_ms          = latency_ms,
            sample_size         = len(attacks) + len(normals),
            normal_sample_size  = len(normals),
        )
        skill.benchmark = result

        # passed() enforces the normal-corpus requirement (audit finding C4).
        status = "PASS ✅" if result.passed(MIN_DETECTION_RATE, MAX_FALSE_POSITIVE) else "FAIL ❌"
        print(f"[SANDBOX] {status} — {result.summary()}")
        return result

    # ─── PRIVATE ─────────────────────────────────────────────────────────────

    def _load_jsonl(self, path: Path) -> list[dict]:
        if not path.exists():
            return []
        rows = []
        with path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return rows

    def _flag_rate(self, samples: list[dict], params: dict) -> float:
        """Fraction of samples the params flag as anomalous (via deviations)."""
        if not samples:
            return 0.0
        flagged = 0
        for s in samples:
            is_anomaly, _ = evaluate_detection(s.get("deviations", {}), params)
            if is_anomaly:
                flagged += 1
        return round(flagged / len(samples), 4)
