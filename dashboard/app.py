"""
AES — Local Dashboard (FastAPI)
Owner: Son Nguyen (AI Infra)

A deployable web app that runs on the SAME host as the pipeline (the Mac). It
reads the artifacts the pipeline already writes and exposes authenticated
learning-skill and demo-control actions for local operators.

Run (from the repo root, with the venv active):
    pip install fastapi "uvicorn[standard]"
    uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
    # open http://localhost:8000

Endpoints:
    GET  /                     → the dashboard page
    GET  /api/state            → fleet + incidents + pending skills + params + history
    POST /api/approve/{id}     → approve a PENDING_HITL skill and inject it live
    POST /api/reject/{id}      → reject a PENDING_HITL skill

Approve/reject go through skills.store + skills.inject directly (no reasoning or
retrieval import), so the dashboard stays lightweight.
"""

import json
import math
import os
import secrets
import time
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse

from skills.store import SkillStore
from skills.inject import Injector
from skills.sandbox import Sandbox
from skills.schema import PENDING_HITL

# Optional Discord deploy notice — never let its absence break the dashboard.
try:
    from discord.discord_alerts import _post as _discord_post
except Exception:
    _discord_post = None

REPO       = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
INCIDENTS  = REPO / "aes_incidents.jsonl"
ACTIVE     = REPO / "config" / "active_detection.json"
FLEET      = REPO / "config" / "fleet_status.json"
REGISTRY   = REPO / "config" / "device_registry.json"
DEMO_CTL   = REPO / "config" / "demo_control.json"
DEFAULT_PARAMS = {"deviation_threshold": 0.5, "simultaneous_threshold": 2}

# A device is marked offline once its last fleet_status.json update is older than this.
# Both the MQTT pipeline and the live demo driver publish at least every 5s, so 3 missed
# beats is a reliable "the publisher process died" signal without flapping on jitter.
STALE_AFTER_SECONDS = 15

app   = FastAPI(title="AES Dashboard")

ALLOWED_ORIGINS = {
    origin.strip() for origin in os.getenv(
        "AES_DASHBOARD_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"
    ).split(",") if origin.strip()
}
ALLOWED_HOSTS = [
    host.strip() for host in os.getenv("AES_DASHBOARD_HOSTS", "localhost,127.0.0.1,testserver").split(",")
    if host.strip()
]

app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

# Let the Next.js web app (web/, dev on :3000) call this API directly during dev.
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(ALLOWED_ORIGINS),
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-AES-Admin-Token"],
)

store = SkillStore()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self' http://localhost:8000 http://127.0.0.1:8000; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def _require_admin(
    request: Request,
    authorization: str | None = Header(default=None),
    x_aes_admin_token: str | None = Header(default=None),
):
    expected = os.getenv("AES_DASHBOARD_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="AES_DASHBOARD_TOKEN must contain at least 32 characters")
    origin = request.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="origin is not allowed")
    supplied = x_aes_admin_token or ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="invalid dashboard token")


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _read_json(path: Path, default):
    try:
        return json.loads(
            path.read_text(),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except Exception:
        return default


def _seconds_since(last_seen: str) -> float:
    """Seconds elapsed since a "HH:MM:SS" last_seen mark (assumes today). Unparseable
    or missing values come back as infinity so the device reads as stale, not crashes."""
    try:
        seen_time = datetime.strptime(last_seen, "%H:%M:%S").time()
    except (ValueError, TypeError):
        return float("inf")
    now = datetime.now()
    seen = datetime.combine(now.date(), seen_time)
    delta = (now - seen).total_seconds()
    return delta if delta >= 0 else delta + 86400  # rolled over midnight


def _read_incidents(limit: int = 20) -> list:
    if not INCIDENTS.exists():
        return []
    rows = []
    for line in INCIDENTS.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(
                    line, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value))
                ))
            except (json.JSONDecodeError, ValueError):
                pass
    return list(reversed(rows))[:limit]   # newest first


def _threshold_history() -> list:
    """Default rule, then each INJECTED skill (threshold + benchmark detection rate) in deploy order."""
    pts = [{"label": "v1 (ship)", "threshold": DEFAULT_PARAMS["deviation_threshold"], "detection_rate": 0.80}]
    latest = {}
    for s in store.load_all():
        latest[s.skill_id] = s
    injected = sorted(
        [s for s in latest.values() if s.status == "INJECTED"],
        key=lambda s: s.created_at,
    )
    for i, s in enumerate(injected, 1):
        pts.append({
            "label": f"deploy {i}",
            "threshold": s.params.get("deviation_threshold"),
            "detection_rate": s.benchmark.detection_rate,
        })
    return pts


# ─── API ──────────────────────────────────────────────────────────────────────

@app.get("/api/state")
def state(_admin=Depends(_require_admin)):
    return {
        "fleet":         _read_json(FLEET, {}),
        "incidents":     _read_incidents(),
        "pending":       [s.to_dict() for s in store.load_by_status(PENDING_HITL)],
        "active_params": _read_json(ACTIVE, DEFAULT_PARAMS),
        "history":       _threshold_history(),
    }


# ─── DEVICES (live, connected-only — powers the device-centric web app) ─────────

_CAMERA_HINTS = ("cam", "camera", "tapo", "c200", "hikvision", "reolink", "webcam", "doorbell")


def _device_kind(model: str) -> str:
    m = (model or "").lower()
    return "camera" if any(h in m for h in _CAMERA_HINTS) else "generic"


def _norm_status(s) -> str:
    v = (s or "").lower()
    if v in ("attack", "attacked", "compromised"):
        return "attack"
    if v in ("elevated", "elevating"):
        return "elevated"
    if v in ("warming", "warmup"):
        return "warming"
    if v in ("offline", "disconnected"):
        return "offline"
    return "clean"


def _default_baseline(model: str) -> dict:
    if any(h in (model or "").lower() for h in ("tapo", "c200")):
        return {"cpu_percent": 16.0, "memory_percent": 44.0, "packet_rate": 28.0, "connection_count": 2}
    return {"cpu_percent": 21.0, "memory_percent": 38.0, "packet_rate": 47.0, "connection_count": 1}


def _finite_float(value, default=0.0) -> float:
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError, OverflowError):
        return default


def _bounded_int(value, default=0) -> int:
    number = _finite_float(value, float(default))
    return max(0, min(1_000_000, int(number)))


@app.get("/api/devices")
def devices(_admin=Depends(_require_admin)):
    """Every device ever seen in fleet_status.json, enriched with registry metadata.
    A device whose last update is older than STALE_AFTER_SECONDS (publisher killed,
    e.g. telemetry_sim.py stopped) is marked offline rather than dropped, so the web
    app can show it as disconnected instead of just making it disappear."""
    registry = _read_json(REGISTRY, {})
    fleet = _read_json(FLEET, {})
    out = []
    for dev_id, fs in fleet.items():
        reg = registry.get(dev_id, {})
        model = reg.get("model", dev_id)
        stale = _seconds_since(fs.get("last_seen", "")) > STALE_AFTER_SECONDS
        out.append({
            "id": dev_id,
            "model": model,
            "kind": _device_kind(model),
            "owner": reg.get("owner", ""),
            "solution_track": reg.get("solution_track", 1),
            "firmware": reg.get("firmware", ""),
            "registry_status": reg.get("status", ""),
            "connected": not stale,
            "status": "offline" if stale else _norm_status(fs.get("status")),
            "metrics": {
                "cpu_percent": _finite_float(fs.get("cpu_percent")),
                "memory_percent": _finite_float(fs.get("memory_percent")),
                "packet_rate": _finite_float(fs.get("packet_rate")),
                "connection_count": _bounded_int(fs.get("connection_count")),
            },
            "baseline": _default_baseline(model),
            "last_seen": fs.get("last_seen", ""),
        })
    return out


@app.post("/api/approve/{skill_id}")
def approve(skill_id: str, _admin=Depends(_require_admin)):
    skill = store.load_latest(skill_id)
    if not skill or skill.status != PENDING_HITL:
        return JSONResponse({"ok": False, "reason": "not pending"}, status_code=400)
    if not Sandbox().benchmark(skill).passed():
        return JSONResponse({"ok": False, "reason": "current authenticated benchmark failed"}, status_code=400)
    try:
        skill.approve("dashboard")
    except ValueError as exc:
        return JSONResponse({"ok": False, "reason": str(exc)}, status_code=503)
    store.save(skill)
    ok = Injector(store).inject(skill)   # writes config/active_detection.json → monitor adopts live
    if ok and _discord_post:
        try:
            _discord_post(
                f"✅ **SKILL DEPLOYED** — `{skill.skill_id}` (v{skill.version})\n"
                f"Approved via dashboard · params {json.dumps(skill.params)}\n"
                f"Benchmark: {skill.benchmark.summary()}"
            )
        except Exception:
            pass
    return JSONResponse({"ok": bool(ok), "skill_id": skill_id, "params": skill.params})


@app.post("/api/reject/{skill_id}")
def reject(skill_id: str, _admin=Depends(_require_admin)):
    skill = store.load_latest(skill_id)
    if not skill or skill.status != PENDING_HITL:
        return JSONResponse({"ok": False, "reason": "not pending"}, status_code=400)
    skill.reject()
    store.save(skill)
    return JSONResponse({"ok": True, "skill_id": skill_id})


# ─── DEMO CONTROL (esp32-cam-01 attack→patch→reset, driven by live_demo.py) ─────
# The cam-01 device screen can drive an explicitly simulated attack story. These
# endpoints only flip a small control file consumed by scripts/live_demo.py; they
# do not execute or claim a real remediation.

@app.post("/api/demo/cam01/attack")
def demo_attack(_admin=Depends(_require_admin)):
    """Start the simulated cam-01 dashboard scenario."""
    DEMO_CTL.write_text(json.dumps({"phase": "attack", "t0": time.time()}))
    return {"ok": True, "phase": "attack"}


@app.post("/api/demo/cam01/reset")
def demo_reset(_admin=Depends(_require_admin)):
    """Reset: cam-01 (and its incident) return to the clean baseline."""
    DEMO_CTL.write_text(json.dumps({"phase": "normal"}))
    return {"ok": True, "phase": "normal"}


@app.get("/api/demo/cam01")
def demo_status(_admin=Depends(_require_admin)):
    return _read_json(DEMO_CTL, {"phase": "normal"})


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")
