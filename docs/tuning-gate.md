# Detector-tuning gate

How AI-proposed detection thresholds are measured and approved before they go live.

After an incident, Hermes proposes new values for the two detection parameters,
`deviation_threshold` (clamped to 0.30–5.0) and `simultaneous_threshold`
(1–4). It does not write executable code. `skills/sandbox.py` replays labelled
samples through the same `evaluate_detection()` function the live monitor uses:

- **detection rate** = flagged ATTACK samples ÷ ATTACK samples, which must be ≥ 0.80;
- **false-positive rate** = flagged NORMAL samples ÷ NORMAL samples, which must be ≤ 0.10;
- at least one ATTACK and one NORMAL sample are required.

Only samples signed by an operator count. Detector-created incidents are not
independent ground truth, so `scripts/label_sample.py` adds an HMAC label with
`AES_BENCHMARK_HMAC_KEY`. Point the gate at the signed corpora with
`AES_BENCHMARK_ATTACKS` and `AES_BENCHMARK_NORMALS`.

Approval happens in one of two places:

- CLI: `python -m skills.hitl approve <skill_id> <approver>` (`list` / `reject` also available);
- dashboard: `POST /api/approve/{skill_id}` with `AES_DASHBOARD_TOKEN`.

Both re-run the benchmark immediately before approving. The approval is
HMAC-signed with `AES_SKILL_APPROVAL_KEY` over the parameters and benchmark,
and `skills/inject.py` refuses a skill whose signature no longer matches. The
Discord webhook announces proposals; approving with a Discord reaction is not
implemented.

Reproduce a gate result from signed corpora:

```bash
export AES_BENCHMARK_HMAC_KEY=<32+ chars>
python scripts/label_sample.py ATTACK sample.json attack_labels.jsonl --reviewer <you>
python scripts/label_sample.py NORMAL normal.json normal_labels.jsonl --reviewer <you>
python -m skills.sandbox --attacks attack_labels.jsonl --normals normal_labels.jsonl \
    --deviation-threshold 0.35 --simultaneous-threshold 2 --json   # exit 0 = PASS
```

No signed benchmark corpus is committed, so the repository contains no gate
results to reproduce. `tests/test_sandbox.py` runs this label-then-benchmark
flow on a small synthetic corpus.

[← Back to README](../README.md)
