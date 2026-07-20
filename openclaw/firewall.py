"""
AES — OpenClaw Firewall Backends
=================================
Owner: Duc Vu (Software/Pipeline)

Platform-abstracted firewall control for Solution 2 (network quarantine of
closed-firmware devices). One interface, three backends:

  IptablesBackend — Linux gateway (Raspberry Pi), locally or over SSH
  PfBackend       — macOS gateway (Mac-as-gateway, per the no-Pi hedge)
  NetshBackend    — Windows host (dev bench)

SAFETY INVARIANTS (red lines from the architecture doc):
  - dry_run() ALWAYS runs before apply() — solution2.py enforces the order.
  - Every input that reaches a command line is validated first: IPs must parse
    with ipaddress.ip_address(), device ids are restricted to [a-z0-9-].
  - No shell=True anywhere — argv lists only.
  - Rules are idempotent and tagged with the device id so remove() can
    surgically roll back exactly what apply() added.
"""

import ipaddress
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class QuarantinePlan:
    device_id: str
    ip:        str

    @property
    def rule_name(self) -> str:
        return f"AES-Quarantine-{self.device_id}"

    def validate(self) -> str | None:
        """Return an error string, or None if the plan is safe to execute."""
        if not re.fullmatch(r"[a-z0-9-]{1,64}", self.device_id):
            return f"unsafe device_id {self.device_id!r} — [a-z0-9-] only"
        try:
            ipaddress.ip_address(self.ip)
        except ValueError:
            return f"invalid IP address {self.ip!r}"
        return None


def _run(argv: list, timeout: int = 20) -> tuple[bool, str]:
    """Run a command; (ok, combined-output-tail). Never raises."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, f"{argv[0]} not found"
    except subprocess.TimeoutExpired:
        return False, f"{argv[0]} timed out after {timeout}s"
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, out[-400:]


# ─── LINUX / RASPBERRY PI ────────────────────────────────────────────────────

class IptablesBackend:
    """
    iptables on the gateway. With ssh_target (e.g. "pi@192.168.4.1") every
    command is executed remotely over SSH (key-based auth; never passwords on
    the command line). Rules live in a dedicated AES_QUARANTINE chain hooked
    into FORWARD, so remove() can clear one device without touching anything else.
    """
    name = "iptables"

    def __init__(self, ssh_target: str | None = None):
        if ssh_target and not re.fullmatch(r"[A-Za-z0-9_.@-]+", ssh_target):
            raise ValueError(f"unsafe SSH target {ssh_target!r}")
        self.ssh_target = ssh_target

    def _argv(self, *ipt_args: str) -> list:
        base = ["iptables", *ipt_args]
        if self.ssh_target:
            return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                    self.ssh_target, "sudo", *base]
        return base

    def available(self) -> tuple[bool, str]:
        if self.ssh_target:
            return _run(self._argv("-L", "-n"))[0], f"iptables via SSH {self.ssh_target}"
        if not shutil.which("iptables"):
            return False, "iptables not installed on this host"
        return True, "local iptables"

    def _ensure_chain(self) -> tuple[bool, str]:
        _run(self._argv("-N", "AES_QUARANTINE"))                    # idempotent — EEXIST ok
        ok, out = _run(self._argv("-C", "FORWARD", "-j", "AES_QUARANTINE"))
        if not ok:
            return _run(self._argv("-I", "FORWARD", "-j", "AES_QUARANTINE"))
        return True, "chain hooked"

    def dry_run(self, plan: QuarantinePlan) -> tuple[bool, str]:
        ok, out = _run(self._argv("-L", "-n"))
        if not ok:
            return False, f"iptables unreachable: {out}"
        already = _run(self._argv("-C", "AES_QUARANTINE", "-s", plan.ip, "-j", "DROP"))[0]
        return True, ("rule already present (idempotent)" if already
                      else f"would DROP src/dst {plan.ip} in AES_QUARANTINE")

    def apply(self, plan: QuarantinePlan) -> tuple[bool, str]:
        ok, out = self._ensure_chain()
        if not ok:
            return False, f"could not hook AES_QUARANTINE chain: {out}"
        for direction in (("-s", plan.ip), ("-d", plan.ip)):
            if not _run(self._argv("-C", "AES_QUARANTINE", *direction, "-j", "DROP"))[0]:
                ok, out = _run(self._argv("-A", "AES_QUARANTINE", *direction, "-j", "DROP"))
                if not ok:
                    return False, f"append failed: {out}"
        return True, f"DROP rules live for {plan.ip} (both directions)"

    def verify(self, plan: QuarantinePlan) -> tuple[bool, str]:
        ok = _run(self._argv("-C", "AES_QUARANTINE", "-s", plan.ip, "-j", "DROP"))[0]
        return ok, "rule verified in chain" if ok else "rule NOT present after apply"

    def remove(self, plan: QuarantinePlan) -> tuple[bool, str]:
        results = [_run(self._argv("-D", "AES_QUARANTINE", *d, "-j", "DROP"))
                   for d in (("-s", plan.ip), ("-d", plan.ip))]
        ok = any(r[0] for r in results)
        return ok, "rules removed" if ok else results[0][1]


# ─── MACOS ───────────────────────────────────────────────────────────────────

class PfBackend:
    """
    pf on macOS (Mac-as-gateway). Uses a persistent address table; requires the
    one-time anchor in /etc/pf.conf:
        table <aes_quarantine> persist
        block drop quick from <aes_quarantine> to any
        block drop quick from any to <aes_quarantine>
    then `sudo pfctl -f /etc/pf.conf -e`.
    """
    name = "pf"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "darwin" or not shutil.which("pfctl"):
            return False, "pfctl not available (not macOS?)"
        return True, "pfctl"

    def dry_run(self, plan: QuarantinePlan) -> tuple[bool, str]:
        ok, out = _run(["pfctl", "-s", "info"])
        if not ok:
            return False, f"pf unreachable (needs sudo?): {out}"
        return True, f"would add {plan.ip} to <aes_quarantine> table"

    def apply(self, plan: QuarantinePlan) -> tuple[bool, str]:
        return _run(["pfctl", "-t", "aes_quarantine", "-T", "add", plan.ip])

    def verify(self, plan: QuarantinePlan) -> tuple[bool, str]:
        ok, out = _run(["pfctl", "-t", "aes_quarantine", "-T", "show"])
        present = ok and plan.ip in out
        return present, "IP present in table" if present else "IP NOT in table after apply"

    def remove(self, plan: QuarantinePlan) -> tuple[bool, str]:
        return _run(["pfctl", "-t", "aes_quarantine", "-T", "delete", plan.ip])


# ─── WINDOWS ─────────────────────────────────────────────────────────────────

class NetshBackend:
    """Windows Defender Firewall via netsh advfirewall (dev-bench enforcement)."""
    name = "netsh"

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32" or not shutil.which("netsh"):
            return False, "netsh not available (not Windows?)"
        return True, "netsh advfirewall"

    def dry_run(self, plan: QuarantinePlan) -> tuple[bool, str]:
        ok, out = _run(["netsh", "advfirewall", "show", "currentprofile"])
        if not ok:
            return False, f"firewall service unreachable: {out}"
        return True, f"would block remoteip={plan.ip} in+out as '{plan.rule_name}'"

    def apply(self, plan: QuarantinePlan) -> tuple[bool, str]:
        for direction in ("in", "out"):
            ok, out = _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={plan.rule_name}", f"dir={direction}", "action=block",
                f"remoteip={plan.ip}",
            ])
            if not ok:
                return False, f"add rule ({direction}) failed — run elevated? {out}"
        return True, f"block rules live for {plan.ip} (in+out)"

    def verify(self, plan: QuarantinePlan) -> tuple[bool, str]:
        ok, out = _run(["netsh", "advfirewall", "firewall", "show", "rule",
                        f"name={plan.rule_name}"])
        present = ok and plan.ip in out
        return present, "rule verified" if present else "rule NOT present after apply"

    def remove(self, plan: QuarantinePlan) -> tuple[bool, str]:
        return _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={plan.rule_name}"])


# ─── SELECTION ───────────────────────────────────────────────────────────────

def detect_backend(ssh_target: str | None = None):
    """
    Pick the enforcement point. GATEWAY_SSH forces the Pi/Linux gateway over
    SSH regardless of the local OS; otherwise enforce on the local host.
    """
    if ssh_target:
        return IptablesBackend(ssh_target=ssh_target)
    if sys.platform.startswith("linux"):
        return IptablesBackend()
    if sys.platform == "darwin":
        return PfBackend()
    return NetshBackend()
