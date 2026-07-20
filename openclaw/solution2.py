"""
AES — OpenClaw Solution 2: Network Quarantine Executor
=======================================================
Owner: Duc Vu (Software/Pipeline)

Execution layer for closed-firmware devices (Tapo C200): the device can't be
patched, so it gets wrapped at the gateway. The rule is derived from the
3-source whitelist model (manufacturer spec + fresh-flash baseline + CVE
exclusion); enforcement is a bidirectional block of the device's IP in a
dedicated, reversible quarantine rule/chain/table.

FLOW (handle() — the interface contract with response_agent.respond()):
  1. Resolve the device IP    — device_registry.json "ip" key, or the
                                AES_DEVICE_IP_<DEVICE_ID> env override.
  2. Validate the plan        — IP must parse, device id must be clean.
  3. Backend availability     — iptables (GATEWAY_SSH → Pi), pf, or netsh.
  4. DRY-RUN — ALWAYS FIRST   — never skipped, red line.
  5. Enforce + verify         — ONLY when AES_FIREWALL_ENFORCE=1.
                                Default is dry-run-only: the plan is logged and
                                the incident is marked "enforced_dryrun", so a
                                dev bench can never knock a real camera offline
                                by accident. Set the env var on the gateway.
  6. Audit trail              — every action (incl. dry-runs and failures)
                                appended to outputs/firewall/actions.jsonl.

Rollback: python -m openclaw.solution2 release <device_id>
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from openclaw.firewall import QuarantinePlan, detect_backend

_REPO_ROOT  = Path(__file__).resolve().parents[1]
_AUDIT_PATH = _REPO_ROOT / "outputs" / "firewall" / "actions.jsonl"


def _audit(record: dict):
    """Append-only audit trail of every firewall decision, enforced or not."""
    _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    record["at"] = datetime.now(timezone.utc).isoformat()
    with open(_AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def _resolve_ip(device_id: str) -> str | None:
    """Registry "ip" key first, then AES_DEVICE_IP_<DEVICE_ID> env override."""
    from agents.monitor_agent import DEVICE_REGISTRY
    ip = (DEVICE_REGISTRY.get(device_id) or {}).get("ip")
    if ip:
        return ip
    return os.getenv(f"AES_DEVICE_IP_{device_id.upper().replace('-', '_')}")


def handle(incident: dict, verdict: dict) -> bool:
    """
    Solution 2 entry point — called by response_agent.handle_solution_2().
    Returns True on success (rule enforced+verified, or dry-run-only mode),
    False on any failure (triggers response_agent's retry/backoff).
    """
    from agents.response_agent import update_incident_fields   # lazy: avoids circular import

    device_id   = incident["device_id"]
    incident_id = incident["incident_id"]
    enforce     = os.getenv("AES_FIREWALL_ENFORCE") == "1"

    print(f"  [SOLUTION 2] Network quarantine for {device_id}")
    update_incident_fields(incident_id, stage="vuln_confirmed")

    # ── Step 1-2: resolve + validate the plan ────────────────────────────────
    ip = _resolve_ip(device_id)
    if not ip:
        print(f"    [ERROR] No IP known for {device_id} — add \"ip\" to "
              f"config/device_registry.json or set AES_DEVICE_IP_"
              f"{device_id.upper().replace('-', '_')}")
        _audit({"device_id": device_id, "incident_id": incident_id,
                "action": "quarantine", "result": "failed", "reason": "no IP"})
        return False

    plan = QuarantinePlan(device_id=device_id, ip=ip)
    err = plan.validate()
    if err:
        print(f"    [ERROR] Unsafe plan rejected: {err}")
        _audit({"device_id": device_id, "incident_id": incident_id,
                "action": "quarantine", "result": "rejected", "reason": err})
        return False
    print(f"    Step 1: Plan — block {ip} bidirectionally as '{plan.rule_name}'")
    print(f"            (3-source whitelist: manufacturer spec + fresh-flash "
          f"baseline + CVE exclusion → everything else drops)")
    update_incident_fields(incident_id, stage="whitelist_built")

    # ── Step 3: pick the enforcement point ───────────────────────────────────
    backend = detect_backend(ssh_target=os.getenv("GATEWAY_SSH"))
    ok, detail = backend.available()
    if not ok:
        print(f"    [ERROR] No usable firewall backend: {detail}")
        _audit({"device_id": device_id, "incident_id": incident_id,
                "action": "quarantine", "result": "failed",
                "reason": f"backend unavailable: {detail}"})
        return False
    print(f"    Step 2: Enforcement point — {backend.name} ({detail})")

    # ── Step 4: DRY-RUN — never skipped (red line) ───────────────────────────
    ok, detail = backend.dry_run(plan)
    print(f"    Step 3: Dry-run — {'OK' if ok else 'FAILED'}: {detail}")
    update_incident_fields(incident_id, stage="dry_run")
    if not ok:
        _audit({"device_id": device_id, "incident_id": incident_id, "ip": ip,
                "backend": backend.name, "action": "dry_run", "result": "failed",
                "reason": detail})
        return False

    if not enforce:
        # Safe default for dev benches: prove the whole path except the write.
        print(f"    Step 4: ENFORCEMENT SKIPPED — AES_FIREWALL_ENFORCE is not set.")
        print(f"            Dry-run passed; set AES_FIREWALL_ENFORCE=1 on the "
              f"gateway to write real rules.")
        update_incident_fields(incident_id, stage="enforced_dryrun",
                               enforcement="dry_run_only")
        _audit({"device_id": device_id, "incident_id": incident_id, "ip": ip,
                "backend": backend.name, "action": "quarantine",
                "result": "dry_run_only"})
        return True

    # ── Step 5: enforce + verify ─────────────────────────────────────────────
    ok, detail = backend.apply(plan)
    print(f"    Step 4: Enforce — {'OK' if ok else 'FAILED'}: {detail}")
    update_incident_fields(incident_id, stage="enforced")
    if not ok:
        _audit({"device_id": device_id, "incident_id": incident_id, "ip": ip,
                "backend": backend.name, "action": "quarantine",
                "result": "failed", "reason": detail})
        return False

    ok, detail = backend.verify(plan)
    print(f"    Step 5: Verify — {'OK' if ok else 'FAILED'}: {detail}")
    if not ok:
        # A rule we can't verify is a rule we don't trust — roll it back.
        removed, rm_detail = backend.remove(plan)
        print(f"    Rollback {'succeeded' if removed else 'FAILED'}: {rm_detail}")
        _audit({"device_id": device_id, "incident_id": incident_id, "ip": ip,
                "backend": backend.name, "action": "quarantine",
                "result": "verify_failed_rolled_back"})
        return False

    update_incident_fields(incident_id, stage="verified", enforcement="live")
    _audit({"device_id": device_id, "incident_id": incident_id, "ip": ip,
            "backend": backend.name, "action": "quarantine", "result": "enforced"})
    print(f"    ✅ {device_id} quarantined at the gateway — traffic drops verified")
    return True


def release(device_id: str) -> bool:
    """Lift a quarantine (CLI: python -m openclaw.solution2 release <device_id>)."""
    ip = _resolve_ip(device_id)
    if not ip:
        print(f"[SOLUTION 2] No IP known for {device_id}")
        return False
    plan = QuarantinePlan(device_id=device_id, ip=ip)
    if plan.validate():
        print(f"[SOLUTION 2] Unsafe plan: {plan.validate()}")
        return False
    backend = detect_backend(ssh_target=os.getenv("GATEWAY_SSH"))
    ok, detail = backend.remove(plan)
    print(f"[SOLUTION 2] Release {device_id} ({ip}): {'OK' if ok else 'FAILED'} — {detail}")
    _audit({"device_id": device_id, "ip": ip, "backend": backend.name,
            "action": "release", "result": "removed" if ok else "failed"})
    return ok


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "release":
        sys.exit(0 if release(sys.argv[2]) else 1)
    print("Usage: python -m openclaw.solution2 release <device_id>")
    sys.exit(1)
