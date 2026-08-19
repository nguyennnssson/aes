"""
AES — Monitor Agent (Pure Detection Logic)
==========================================
Owner: Son Nguyen (AI Infra)
Moved to: agents/monitor_agent.py

WHAT IT DOES:
  Implements EWMA (Exponentially Weighted Moving Average) anomaly detection.
  Tracks what "normal" looks like for each device, flags coordinated metric spikes.

WHAT IT DOES NOT DO:
  No MQTT. No networking. No side effects. This is pure, importable logic.
  The MQTT subscriber lives in agents/monitor_agent_mqtt.py.

HOW IT FITS IN THE PIPELINE:
  telemetry (from Vy's ESP32 agent or telemetry_sim.py)
    → MQTT → monitor_agent_mqtt.py
    → MonitorAgent.check(telemetry) [this file]
    → AnomalyResult → Intel Agent → Hermes → Response Agent → Discord

TELEMETRY CONTRACT (Vy):
  Every MQTT message must be JSON matching the Telemetry dataclass:
    device_id, timestamp, cpu_percent, memory_percent, packet_rate, connection_count
  Topic format: aes/telemetry/{device_id}

DETECTION THRESHOLDS:
  WARMUP_SAMPLES = 12       (1 minute of 5-second readings to establish baseline)
  DEVIATION_THRESHOLD = 0.5 (50% above normal to count as suspicious)
  SIMULTANEOUS_THRESHOLD = 2 (2+ metrics must spike at once — single spikes are normal)

No API key needed. No Mac Studio needed. Pure Python.
"""

import json
import os
import time
import hashlib
import hmac
import math
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from collections import deque

# ─── DEVICE REGISTRY ─────────────────────────────────────────────────────────
# Loaded from device_registry.json — single source of truth for all components.
# To add a device: edit device_registry.json only. No code changes needed.

_REGISTRY_PATH  = Path(__file__).parent.parent / "config" / "device_registry.json"
_BASELINE_PATH  = Path(__file__).parent.parent / "config" / "ewma_baseline.json"
# Live-tunable detection params written by the Solution 3 learning loop (inject.py).
# Absent file = use class defaults below. Re-read on change so the RUNNING monitor
# process picks up an injected skill with no restart and no importlib.reload.
_ACTIVE_PARAMS_PATH = Path(__file__).parent.parent / "config" / "active_detection.json"

def _load_registry() -> dict:
    try:
        with open(_REGISTRY_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[WARNING] device_registry.json not found at {_REGISTRY_PATH}")
        return {}

DEVICE_REGISTRY = _load_registry()


# ─── ACTIVE DETECTION PARAMS (Solution 3) ────────────────────────────────────
# A "skill" is a small set of EWMA detection params — NOT executable code.
# This file is the single live source of truth, polled by mtime so the long-
# running monitor process adopts an injected skill within one reading.

# Safe bounds for live detection params — the single source of truth, shared by
# the live loader below and the Solution 3 learning loop (skills/hitl.py) so a
# hand-edited or Hermes-proposed value can never break evaluate_detection().
PARAM_BOUNDS = {
    "deviation_threshold":    (0.30, 5.0),
    "simultaneous_threshold": (1, 4),
}


def validate_detection_params(raw: dict) -> dict:
    """Keep only known keys, coerce types, and clamp to PARAM_BOUNDS. Junk values
    are dropped rather than raised — a corrupt params file must never crash the
    monitor (REVIEW P2-16)."""
    out = {}
    if not isinstance(raw, dict):
        return out
    for key, (lo, hi) in PARAM_BOUNDS.items():
        if key not in raw:
            continue
        try:
            val = float(raw[key])
        except (TypeError, ValueError):
            continue
        if not math.isfinite(val):
            continue
        val = max(lo, min(hi, val))
        out[key] = int(val) if key == "simultaneous_threshold" else val
    return out


_active_params_cache = {"mtime": None, "params": {}}

def load_active_params() -> dict:
    """
    Return the currently injected detection params (validated + clamped), or {}
    for class defaults. Polls the file's mtime; only re-reads (and logs) when it
    actually changes. Any read/parse error keeps the last-known-good params —
    never raises into check().
    """
    try:
        mtime = _ACTIVE_PARAMS_PATH.stat().st_mtime
    except FileNotFoundError:
        return {}
    if _active_params_cache["mtime"] != mtime:
        try:
            with open(_ACTIVE_PARAMS_PATH) as f:
                loaded = json.load(f)
            # Validate on load so a hand-edited non-numeric threshold can't make
            # evaluate_detection() raise on every reading (paho would swallow the
            # exception → silent detection death).
            _active_params_cache["params"] = validate_detection_params(loaded)
            _active_params_cache["mtime"] = mtime
            print(f"[MONITOR] Active detection params updated: {_active_params_cache['params']}")
        except Exception as e:
            print(f"[MONITOR] Could not load active params — keeping previous ({e})")
    return _active_params_cache["params"]


# ─── TELEMETRY SCHEMA ────────────────────────────────────────────────────────
# This is the contract between Vy's ESP32 agent and this Monitor Agent.
# Every MQTT message must match this structure exactly.

@dataclass
class Telemetry:
    device_id:        str    # e.g. "esp32-cam-01"
    timestamp:        str    # ISO format: "2026-05-24T10:30:00Z"
    cpu_percent:      float  # 0.0 – 100.0
    memory_percent:   float  # 0.0 – 100.0
    packet_rate:      float  # packets per second
    connection_count: int    # number of active TCP connections

    def validate(self) -> list[str]:
        """Returns a list of validation errors. Empty list = valid."""
        errors = []
        numeric = {
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "packet_rate": self.packet_rate,
            "connection_count": self.connection_count,
        }
        for name, value in numeric.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                errors.append(f"{name} must be a finite number")
        if errors:
            return errors
        if not (0.0 <= self.cpu_percent <= 100.0):
            errors.append(f"cpu_percent out of range: {self.cpu_percent}")
        if not (0.0 <= self.memory_percent <= 100.0):
            errors.append(f"memory_percent out of range: {self.memory_percent}")
        if not (0.0 <= self.packet_rate <= 1_000_000.0):
            errors.append(f"packet_rate out of range: {self.packet_rate}")
        if not (0 <= self.connection_count <= 1_000_000):
            errors.append(f"connection_count out of range: {self.connection_count}")
        # Security: device_id must be non-empty and alphanumeric + hyphens only
        # (no injection). `all()` over an empty string is vacuously True, so the
        # emptiness check must be explicit (REVIEW P2-16).
        if (not isinstance(self.device_id, str) or not self.device_id or len(self.device_id) > 64
                or not all(c.isascii() and (c.isalnum() or c == '-') for c in self.device_id)):
            errors.append(f"device_id invalid or empty: {self.device_id!r}")
        try:
            parsed = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                errors.append("timestamp must include a timezone")
            else:
                age = abs((datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds())
                if age > 300:
                    errors.append(f"timestamp outside 5-minute freshness window: {self.timestamp}")
        except (AttributeError, TypeError, ValueError):
            errors.append(f"timestamp is not valid ISO-8601: {self.timestamp!r}")
        return errors


# ─── EWMA STATE ──────────────────────────────────────────────────────────────
# EWMA = Exponentially Weighted Moving Average.
# It tracks a "rolling average" that adapts over time but weights recent readings more.
# Think of it as the system's memory of what normal looks like for each device.

@dataclass
class EWMAState:
    # The current "normal" baseline for each metric
    cpu:         float = 20.0   # start with reasonable defaults
    memory:      float = 40.0
    packet_rate: float = 50.0
    connections: float = 3.0

    # How many readings we've seen (used to avoid false alarms on startup)
    sample_count: int = 0

    # ALPHA controls how fast the baseline adapts.
    # 0.1 = slow adaptation (resistant to spikes but slow to update)
    # 0.3 = faster adaptation
    # We use 0.1 so a single spike doesn't rewrite what "normal" means.
    ALPHA: float = field(default=0.1, repr=False)

    def update(self, t: Telemetry):
        """Update the baseline with a new normal reading."""
        self.cpu         = self.ALPHA * t.cpu_percent      + (1 - self.ALPHA) * self.cpu
        self.memory      = self.ALPHA * t.memory_percent   + (1 - self.ALPHA) * self.memory
        self.packet_rate = self.ALPHA * t.packet_rate      + (1 - self.ALPHA) * self.packet_rate
        self.connections = self.ALPHA * t.connection_count + (1 - self.ALPHA) * self.connections
        self.sample_count += 1


# ─── ANOMALY RESULT ──────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    device_id:   str
    timestamp:   str
    is_anomaly:  bool
    confidence:  float        # 0.0 – 1.0
    reason:      str          # human-readable explanation
    deviations:  dict         # which metrics spiked and by how much
    baseline:    dict         # what "normal" looked like at time of detection


# ─── MONITOR AGENT ───────────────────────────────────────────────────────────

class MonitorAgent:
    """
    One MonitorAgent per device. Tracks that device's EWMA baseline
    and checks each new telemetry reading for anomalies.
    """

    # How many samples to collect before trusting the baseline
    # (avoids false alarms on startup when baseline = defaults)
    WARMUP_SAMPLES = 12   # 1 minute of 5-second readings

    # A metric must deviate by this much from baseline to count as suspicious
    DEVIATION_THRESHOLD = 0.5   # 50% above normal

    # This many metrics must spike simultaneously to trigger an anomaly alert
    # (single-metric spikes happen normally; coordinated spikes = attack)
    SIMULTANEOUS_THRESHOLD = 2

    # Floor used as the deviation denominator when a device's learned baseline has
    # settled near zero (e.g. an idle camera with packet_rate≈0). Without this, a
    # baseline of 0.0003 turns a tiny absolute blip into a "+17677%" spike and
    # fires a false anomaly. The learned EWMA baseline itself is left untouched —
    # only the deviation *calculation* is floored.
    MIN_BASELINE = {"cpu": 5.0, "memory": 5.0, "packet_rate": 5.0, "connections": 1.0}

    # ── Sustained / low-and-slow detection (stateful) ─────────────────────────
    # The instantaneous rule above needs SIMULTANEOUS_THRESHOLD metrics to spike
    # in the SAME reading. A patient attacker can hold each metric just UNDER the
    # spike threshold and never trip it. This guard fires when 2+ metrics stay
    # "warm" (>= SUSTAINED_WATCH over baseline) for the whole window — the
    # coordinated low-and-slow signature the snapshot rule structurally misses.
    # (A single sustained metric is left to EWMA, which absorbs it as a genuine
    # level shift; flagging it would false-positive on normal load changes.)
    SUSTAINED_WINDOW = 6     # readings to look back (~30s at a 5s cadence)
    SUSTAINED_WATCH  = 0.35  # "warm" = >=35% over baseline (above jitter, below a spike)
    SUSTAINED_HITS   = 6     # must be warm in this many of the window (6/6 = truly sustained)

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.ewma = self._load_baseline()
        self.dev_history = deque(maxlen=self.SUSTAINED_WINDOW)

    def _load_baseline(self) -> EWMAState:
        """Load saved EWMA baseline from disk. Falls back to fresh state on any error."""
        try:
            with open(_BASELINE_PATH) as f:
                data = json.load(f)
            if self.device_id not in data:
                return EWMAState()
            d = data[self.device_id]
            state = EWMAState(
                cpu=d["cpu"],
                memory=d["memory"],
                packet_rate=d["packet_rate"],
                connections=d["connections"],
                sample_count=max(d.get("sample_count", 0), self.WARMUP_SAMPLES),
            )
            print(f"[MONITOR] Loaded baseline for {self.device_id} — skipping warmup")
            return state
        except Exception:
            return EWMAState()

    # Throttle baseline persistence: the learned baseline drifts slowly, so
    # writing it on every reading (~0.8/s across the fleet) is wasteful and — when
    # non-atomic — risks corrupting the committed pre-seeded baseline on a crash.
    _SAVE_EVERY = 10

    def _save_baseline(self):
        """Persist current EWMA state to disk, atomically and throttled (excludes
        ALPHA — it's a constant)."""
        if self.ewma.sample_count % self._SAVE_EVERY != 0:
            return
        try:
            existing = {}
            if _BASELINE_PATH.exists():
                with open(_BASELINE_PATH) as f:
                    existing = json.load(f)
            existing[self.device_id] = {
                "cpu":          round(self.ewma.cpu, 4),
                "memory":       round(self.ewma.memory, 4),
                "packet_rate":  round(self.ewma.packet_rate, 4),
                "connections":  round(self.ewma.connections, 4),
                "sample_count": self.ewma.sample_count,
            }
            _BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write (tmp + replace) so a crash mid-write can't truncate the
            # committed pre-seeded baseline (REVIEW P2-14).
            tmp = _BASELINE_PATH.with_suffix(".json.tmp")
            with open(tmp, "w") as f:
                json.dump(existing, f, indent=2)
            os.replace(tmp, _BASELINE_PATH)
        except Exception as e:
            print(f"[MONITOR] Warning: could not save baseline — {e}")

    def _deviation(self, current: float, baseline: float) -> float:
        """
        How far is 'current' above the baseline, as a fraction?
        e.g. baseline=20, current=40 → deviation=1.0 (100% above normal)
        Returns 0.0 if current is at or below baseline (we only care about spikes up).
        """
        if baseline <= 0:
            return 0.0
        return max(0.0, (current - baseline) / baseline)

    def _sustained_check(self, history) -> dict:
        """
        Low-and-slow guard: catch metrics held just under the spike threshold but
        elevated across the whole window. Returns {metric: mean_deviation} for the
        sustained-warm metrics, but only when 2+ are jointly sustained (the
        coordinated throttled-attack signature). Empty = nothing sustained.
        Pure read over recent history — no I/O, no state mutation.
        """
        if len(history) < self.SUSTAINED_WINDOW:
            return {}
        warm = {}
        for metric in ("cpu", "memory", "packet_rate", "connections"):
            vals = [h.get(metric, 0.0) for h in history]
            if sum(1 for v in vals if v >= self.SUSTAINED_WATCH) >= self.SUSTAINED_HITS:
                warm[metric] = sum(vals) / len(vals)
        return warm if len(warm) >= 2 else {}

    def check(self, t: Telemetry) -> AnomalyResult:
        """
        Main method. Call this on every telemetry reading.
        Returns an AnomalyResult with is_anomaly=True if an attack is suspected.
        """
        # Step 1: validate the telemetry (reject malformed/injected data)
        errors = t.validate()
        if errors:
            return AnomalyResult(
                device_id=t.device_id,
                timestamp=t.timestamp,
                is_anomaly=False,
                confidence=0.0,
                reason=f"INVALID TELEMETRY — rejected: {'; '.join(errors)}",
                deviations={},
                baseline={}
            )

        # Step 2: still warming up — collect baseline, don't alert yet
        if self.ewma.sample_count < self.WARMUP_SAMPLES:
            self.ewma.update(t)
            return AnomalyResult(
                device_id=t.device_id,
                timestamp=t.timestamp,
                is_anomaly=False,
                confidence=0.0,
                reason=f"Warming up baseline ({self.ewma.sample_count}/{self.WARMUP_SAMPLES} samples)",
                deviations={},
                baseline={}
            )

        # Step 3: calculate how far each metric deviates from its baseline
        deviations = {
            "cpu":         self._deviation(t.cpu_percent,      max(self.ewma.cpu,         self.MIN_BASELINE["cpu"])),
            "memory":      self._deviation(t.memory_percent,   max(self.ewma.memory,      self.MIN_BASELINE["memory"])),
            "packet_rate": self._deviation(t.packet_rate,      max(self.ewma.packet_rate, self.MIN_BASELINE["packet_rate"])),
            "connections": self._deviation(t.connection_count, max(self.ewma.connections, self.MIN_BASELINE["connections"])),
        }

        # Step 4+5: apply the active detection params (live-tunable via Solution 3).
        # Falls back to this class's defaults when no skill has been injected.
        # Same helper is used by the sandbox, so live and benchmark logic agree.
        inst_anomaly, spiking = evaluate_detection(deviations, load_active_params())

        # Step 5b: sustained / low-and-slow guard (stateful). Record this reading,
        # then — only if the snapshot rule didn't already fire — look back over the
        # window for 2+ metrics held warm the whole time. Catches throttled attacks
        # that never spike SIMULTANEOUS_THRESHOLD metrics in a single reading.
        self.dev_history.append(deviations)
        sustained = {} if inst_anomaly else self._sustained_check(self.dev_history)
        is_anomaly = inst_anomaly or bool(sustained)

        # Step 6: confidence = average deviation of whichever signal fired (capped)
        signal = spiking if inst_anomaly else sustained
        confidence = 0.0
        if signal:
            confidence = min(1.0, (sum(signal.values()) / len(signal)) / 2.0)

        # Step 7: build a human-readable reason
        if inst_anomaly:
            spike_descriptions = [
                f"{m} +{int(d*100)}% above normal"
                for m, d in spiking.items()
            ]
            reason = f"ANOMALY DETECTED — {', '.join(spike_descriptions)}"
        elif sustained:
            slow_descriptions = [
                f"{m} +{int(d*100)}% held for {self.SUSTAINED_WINDOW} readings"
                for m, d in sustained.items()
            ]
            reason = f"SUSTAINED ANOMALY (low-and-slow) — {', '.join(slow_descriptions)}"
        elif spiking:
            reason = f"Elevated but below threshold: {list(spiking.keys())}"
        else:
            reason = "Normal"

        # Step 8: update the baseline on normal readings, but FREEZE it when the
        # reading looks like a low-and-slow attack — i.e. 2+ metrics are jointly
        # elevated (>=30%), the stealth signature. A single jittery metric (e.g. a
        # low-baseline connection count going 1->2->3) still updates the baseline,
        # so normal jitter doesn't get frozen in as permanently "elevated." Only
        # correlated multi-metric elevation freezes it, preventing boiling-frog
        # poisoning without starving the baseline.
        elevated = sum(1 for d in deviations.values() if d >= 0.3)
        if not is_anomaly and elevated < 2:
            self.ewma.update(t)
            self._save_baseline()

        return AnomalyResult(
            device_id=t.device_id,
            timestamp=t.timestamp,
            is_anomaly=is_anomaly,
            confidence=round(confidence, 3),
            reason=reason,
            deviations={k: round(v, 3) for k, v in deviations.items()},
            baseline={
                "cpu":         round(self.ewma.cpu, 1),
                "memory":      round(self.ewma.memory, 1),
                "packet_rate": round(self.ewma.packet_rate, 1),
                "connections": round(self.ewma.connections, 1),
            }
        )


# ─── DETECTION DECISION (shared by live monitor + sandbox) ───────────────────

def evaluate_detection(deviations: dict, params: dict) -> tuple[bool, dict]:
    """
    Decide if a set of metric deviations constitutes an anomaly, given params.
    Pure arithmetic — no exec, no I/O. This is the ONLY place the anomaly rule
    lives, so MonitorAgent.check() (live) and Sandbox.benchmark() (replay) can
    never diverge.

    params keys (all optional; fall back to MonitorAgent defaults):
        deviation_threshold    — fraction above baseline to count as a spike
        simultaneous_threshold — how many metrics must spike at once
    Returns (is_anomaly, spiking_metrics_dict).
    """
    safe_params = validate_detection_params(params)
    dev_threshold = safe_params.get("deviation_threshold", MonitorAgent.DEVIATION_THRESHOLD)
    sim_threshold = safe_params.get("simultaneous_threshold", MonitorAgent.SIMULTANEOUS_THRESHOLD)
    clean = {}
    if isinstance(deviations, dict):
        for metric in ("cpu", "memory", "packet_rate", "connections"):
            value = deviations.get(metric)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
                clean[metric] = max(0.0, float(value))
    spiking = {m: d for m, d in clean.items() if d >= dev_threshold}
    return len(spiking) >= sim_threshold, spiking


# ─── INCIDENT LOG ────────────────────────────────────────────────────────────

LOG_PATH = Path("./aes_incidents.jsonl")    # one JSON object per line
HASH_PATH = Path("./aes_incidents.hashes")  # tamper-evident hash ledger
EVENT_PATH = Path("./aes_incident_events.jsonl")
EVENT_HEAD_PATH = Path("./aes_incident_events.head")
NORMALS_PATH = Path("./aes_normals.jsonl")  # sampled normal readings (sandbox FP corpus)

# The MQTT callback and remediation worker both update incident state. One shared
# re-entrant lock prevents a read/replace update from dropping an incident that
# was appended concurrently. It also serializes the audit event and projection.
_INCIDENT_LOCK = threading.RLock()


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _audit_digest(payload: str, algorithm: str | None = None) -> str:
    key = os.getenv("AES_AUDIT_HMAC_KEY", "").encode("utf-8")
    selected = algorithm or ("hmac-sha256" if key else "sha256")
    if selected == "hmac-sha256":
        if not key:
            return ""
        return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _append_audit_event(incident_id: str, event_type: str, payload: dict):
    """Append a full-state audit event chained to the prior event.

    Set AES_AUDIT_HMAC_KEY in every production process. Without it the chain is
    useful for accidental-corruption detection only; production startup rejects
    that mode in monitor_agent_mqtt.main().
    """
    previous = "GENESIS"
    sequence = 1
    if EVENT_PATH.exists():
        lines = [line for line in EVENT_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last = json.loads(lines[-1])
            previous = last["signature"]
            sequence = int(last["sequence"]) + 1
    event = {
        "sequence": sequence,
        "at": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "event_type": event_type,
        "payload": payload,
        "previous": previous,
        "algorithm": "hmac-sha256" if os.getenv("AES_AUDIT_HMAC_KEY") else "sha256",
    }
    event["signature"] = _audit_digest(_canonical(event))
    with open(EVENT_PATH, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    head = {"sequence": sequence, "signature": event["signature"], "algorithm": event["algorithm"]}
    head["auth"] = _audit_digest(_canonical(head))
    tmp = EVENT_HEAD_PATH.with_suffix(".head.tmp")
    tmp.write_text(json.dumps(head), encoding="utf-8")
    os.replace(tmp, EVENT_HEAD_PATH)


def _ensure_audit_seeded():
    """Import legacy projection rows once before the first chained event."""
    if (EVENT_PATH.exists() and EVENT_PATH.stat().st_size) or not LOG_PATH.exists():
        return
    for raw in LOG_PATH.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        incident_id = entry.get("incident_id")
        if incident_id:
            _append_audit_event(incident_id, "detected", entry)


def update_incident_entry(incident_id: str, fields: dict) -> bool:
    """Atomically update the incident projection and record every changed field."""
    with _INCIDENT_LOCK:
        if not LOG_PATH.exists():
            return False
        _ensure_audit_seeded()
        updated = []
        found = False
        for line in LOG_PATH.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                updated.append(line)
                continue
            if entry.get("incident_id") == incident_id:
                entry.update(fields)
                found = True
            updated.append(json.dumps(entry, allow_nan=False))
        if not found:
            return False
        _append_audit_event(incident_id, "updated", fields)
        tmp = LOG_PATH.with_suffix(".jsonl.tmp")
        tmp.write_text("\n".join(updated) + "\n", encoding="utf-8")
        os.replace(tmp, LOG_PATH)
        return True


def write_normal_sample(result: AnomalyResult):
    """
    Append a post-warmup NORMAL reading to the false-positive corpus.
    The sandbox replays these to measure a skill's false-positive rate — without
    them the FP gate is untestable (it would always read 0%).
    """
    entry = {
        "timestamp":  result.timestamp,
        "device_id":  result.device_id,
        "status":     "UNVERIFIED_NORMAL",
        "label_source": "device-telemetry-unverified",
        "deviations": result.deviations,
        "baseline":   result.baseline,
    }
    with open(NORMALS_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _incident_core(entry: dict) -> str:
    """
    Canonical string of the IMMUTABLE detection facts — the basis for the
    tamper-evident hash. Excludes mutable fields (status, resolved_at, verdict)
    so resolving an incident later doesn't invalidate its hash (audit finding M5).
    """
    core = {k: entry.get(k) for k in ("incident_id", "timestamp", "device_id", "deviations")}
    return json.dumps(core, sort_keys=True)


def verify_incident_log() -> list:
    """
    Recompute each incident's immutable-core hash and compare against the ledger.
    Returns a list of problems (empty list = log intact). This is the verifier
    the hash ledger never had (audit finding M5).

    Run: python -c "from agents.monitor_agent import verify_incident_log as v; print(v() or 'OK')"
    """
    problems = []
    if EVENT_PATH.exists() and EVENT_PATH.stat().st_size:
        projected = {}
        previous = "GENESIS"
        expected_sequence = 1
        last_event = None
        for raw in EVENT_PATH.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                event = json.loads(raw)
                signature = event.pop("signature")
            except (json.JSONDecodeError, KeyError):
                problems.append("unparseable audit event")
                continue
            if event.get("sequence") != expected_sequence:
                problems.append(f"audit sequence break at {event.get('sequence')}")
            if event.get("previous") != previous:
                problems.append(f"audit chain break at sequence {event.get('sequence')}")
            if _audit_digest(_canonical(event), event.get("algorithm")) != signature:
                problems.append(f"audit signature mismatch at sequence {event.get('sequence')}")
            iid = event.get("incident_id")
            if event.get("event_type") == "detected":
                projected[iid] = dict(event.get("payload") or {})
            elif event.get("event_type") == "updated" and iid in projected:
                projected[iid].update(event.get("payload") or {})
            previous = signature
            expected_sequence += 1
            last_event = {"sequence": event.get("sequence"), "signature": signature,
                          "algorithm": event.get("algorithm")}

        if last_event and EVENT_HEAD_PATH.exists():
            try:
                head = json.loads(EVENT_HEAD_PATH.read_text(encoding="utf-8"))
                auth = head.pop("auth")
                if head != last_event or _audit_digest(_canonical(head), head.get("algorithm")) != auth:
                    problems.append("audit head mismatch — log may be truncated")
            except (json.JSONDecodeError, KeyError):
                problems.append("audit head is invalid")
        elif last_event:
            problems.append("audit head missing — log may be truncated")

        actual = {}
        if LOG_PATH.exists():
            for raw in LOG_PATH.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(raw)
                    actual[item.get("incident_id")] = item
                except json.JSONDecodeError:
                    problems.append("unparseable log line")
        for iid, expected in projected.items():
            if actual.get(iid) != expected:
                problems.append(f"{iid}: projection differs from authenticated audit history")
        for iid in actual.keys() - projected.keys():
            problems.append(f"{iid}: projection has no audit history")
        return problems

    if not LOG_PATH.exists() or not HASH_PATH.exists():
        return ["incident log or hash ledger missing"]

    ledger = {}
    for line in HASH_PATH.read_text().splitlines():
        if ":" in line:
            iid, h = line.split(":", 1)
            ledger[iid] = h

    log_ids = set()
    for line in LOG_PATH.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            problems.append("unparseable log line")
            continue
        iid = entry.get("incident_id", "?")
        log_ids.add(iid)
        expected = ledger.get(iid)
        if expected is None:
            problems.append(f"{iid}: missing from hash ledger")
        elif hashlib.sha256(_incident_core(entry).encode()).hexdigest() != expected:
            problems.append(f"{iid}: hash mismatch — tampered")

    # Reverse direction (audit finding, REVIEW P1-11): an incident in the ledger
    # but absent from the log was DELETED. Without this check, dropping a whole
    # log line (not just editing it) went undetected.
    for iid in ledger:
        if iid not in log_ids:
            problems.append(f"{iid}: in hash ledger but missing from log — deleted?")
    return problems


def initialize_incident_audit(production: bool = False) -> list[str]:
    """Validate existing history and migrate a valid legacy ledger to events.

    Callers must refuse state-changing work when the returned list is non-empty.
    This prevents a tampered projection or truncated event chain from being used
    as the authorization basis for a remediation.
    """
    with _INCIDENT_LOCK:
        if production and len(os.getenv("AES_AUDIT_HMAC_KEY", "")) < 32:
            return ["AES_AUDIT_HMAC_KEY must contain at least 32 characters"]
        event_present = EVENT_PATH.exists() and EVENT_PATH.stat().st_size > 0
        if event_present:
            return verify_incident_log()
        if EVENT_HEAD_PATH.exists():
            return ["audit head exists without an event log"]
        any_legacy = LOG_PATH.exists() or HASH_PATH.exists()
        if not any_legacy:
            return []
        legacy_problems = verify_incident_log()
        if legacy_problems:
            return legacy_problems
        _ensure_audit_seeded()
        return verify_incident_log()


def write_incident_log(result: AnomalyResult, device_info: dict):
    """
    Writes an anomaly event to the incident log.
    The immutable detection facts are hashed and stored separately, so tampering
    with the log is detectable via verify_incident_log() even after status edits.
    """
    entry = {
        "incident_id":   f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}-{result.device_id}",
        "timestamp":     result.timestamp,
        "device_id":     result.device_id,
        "device_model":  device_info.get("model", "unknown"),
        "solution_track": device_info.get("solution_track", 0),
        "confidence":    result.confidence,
        "reason":        result.reason,
        "deviations":    result.deviations,
        "baseline":      result.baseline,
        "status":        "OPEN",  # remains open until enforcement is independently verified
        "stage":         "monitor_logged",  # live pipeline progress for the dashboard
    }

    with _INCIDENT_LOCK:
        _ensure_audit_seeded()
        _append_audit_event(entry["incident_id"], "detected", entry)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, allow_nan=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

        # Retained for backward compatibility with existing tooling. The event
        # chain above is authoritative and covers later status/verdict changes.
        entry_hash = hashlib.sha256(_incident_core(entry).encode()).hexdigest()
        with open(HASH_PATH, "a", encoding="utf-8") as f:
            f.write(f"{entry['incident_id']}:{entry_hash}\n")

    return entry["incident_id"]


# ─── QUICK TEST ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("AES — Monitor Agent Test\n")

    agent = MonitorAgent("esp32-cam-01")

    # Phase 1: feed 15 normal readings to warm up the baseline
    print("Phase 1: Building baseline (15 normal readings)...")
    for i in range(15):
        normal = Telemetry(
            device_id="esp32-cam-01",
            timestamp=datetime.now(timezone.utc).isoformat(),
            cpu_percent=20.0 + (i % 3),     # normal: ~20-22%
            memory_percent=38.0 + (i % 2),   # normal: ~38-40%
            packet_rate=45.0 + (i % 5),      # normal: ~45-50 pps
            connection_count=2 + (i % 2),    # normal: 2-3 connections
        )
        result = agent.check(normal)
        print(f"  [{i+1:2d}] {result.reason}")

    print()

    # Phase 2: simulate a Mirai-style botnet attack
    # CPU spikes as device is used for DDoS, packet rate explodes
    print("Phase 2: Simulating Mirai botnet attack...")
    attack_readings = [
        Telemetry("esp32-cam-01", datetime.now(timezone.utc).isoformat(),
                  cpu_percent=85.0, memory_percent=42.0,
                  packet_rate=480.0, connection_count=47),
        Telemetry("esp32-cam-01", datetime.now(timezone.utc).isoformat(),
                  cpu_percent=92.0, memory_percent=45.0,
                  packet_rate=510.0, connection_count=52),
    ]

    for reading in attack_readings:
        result = agent.check(reading)
        print(f"\n  {'🚨 ' if result.is_anomaly else '  '}{result.reason}")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Deviations: {result.deviations}")
        print(f"  Baseline:   {result.baseline}")

        if result.is_anomaly:
            device_info = DEVICE_REGISTRY.get(result.device_id, {})
            incident_id = write_incident_log(result, device_info)
            print(f"\n  ✅ Incident logged: {incident_id}")
            print(f"  → Routing to Solution {device_info.get('solution_track')} pipeline (Duc's job)")

    print()

    # Phase 3: test the security validation (prompt injection attempt)
    print("Phase 3: Simulating prompt injection attempt in telemetry...")
    malicious = Telemetry(
        device_id="esp32-cam-01; DROP TABLE incidents; --",  # injection attempt
        timestamp=datetime.now(timezone.utc).isoformat(),
        cpu_percent=20.0,
        memory_percent=38.0,
        packet_rate=45.0,
        connection_count=2,
    )
    result = agent.check(malicious)
    print(f"  Result: {result.reason}")
    print(f"  {'✅ Correctly rejected' if not result.is_anomaly else '❌ Should have been rejected'}")
