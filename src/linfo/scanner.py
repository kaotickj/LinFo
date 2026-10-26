"""Assemble a local, read-only assessment."""
from __future__ import annotations
import json
import os
import platform
import socket
import threading
from datetime import datetime, timezone
import math
from .checks import hardening_checks
from .models import AuditReport, Finding
from .probe import Probe, ProbeCancelled
from .management import detect_platform


def os_pretty(probe: Probe) -> str:
    data = probe.read("/etc/os-release") or ""
    for line in data.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.system()


def inventory(probe: Probe, target: dict | None = None) -> dict:
    platform_info = detect_platform()
    info = target if target is not None else {}
    info.update({
        "operating_system": os_pretty(probe),
        "distribution_id": platform_info.distro_id,
        "package_manager": platform_info.package_manager or "Unsupported/undetected",
        "admin_group": platform_info.admin_group,
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "root_privileges": os.geteuid() == 0,
        "desktop": os.environ.get("XDG_CURRENT_DESKTOP", "Not detected"),
    })
    mem = probe.read("/proc/meminfo", 65536) or ""
    for line in mem.splitlines():
        if line.startswith("MemTotal:"):
            try:
                info["ram_gib"] = round(int(line.split()[1]) / 1048576, 2)
            except (ValueError, IndexError):
                pass
    for key, cmd in [("uptime", ("uptime", "-p")), ("virtualization", ("systemd-detect-virt",)),
                     ("cpu", ("lscpu",)), ("block_devices", ("lsblk", "-J", "-o", "NAME,SIZE,FSTYPE,MOUNTPOINT")),
                     ("interfaces", ("ip", "-j", "address", "show")),
                     ("default_routes", ("ip", "route", "show", "default"))]:
        probe.check_cancelled()
        if not probe.which(cmd[0]):
            continue
        r = probe.run(*cmd, timeout=8)
        if not r.ok:
            continue
        if key in ("interfaces", "block_devices"):
            try:
                parsed = json.loads(r.out)
                if key == "interfaces":
                    info[key] = [{"name": obj.get("ifname"), "state": obj.get("operstate"),
                                  "addresses": [a.get("local") for a in obj.get("addr_info", [])
                                                if a.get("family") in ("inet", "inet6")],
                                  "mac": obj.get("address", "")}
                                 for obj in parsed if obj.get("ifname") != "lo"]
                else:
                    info[key] = parsed.get("blockdevices", [])[:40]
            except (TypeError, ValueError):
                pass
        elif key == "cpu":
            for line in r.out.splitlines():
                if line.startswith("Model name:"):
                    info[key] = line.split(":", 1)[1].strip()
                    break
        elif key == "default_routes":
            info[key] = r.out.strip().splitlines()[:5]
        else:
            info[key] = r.out.strip()[:200]
    return info


def scan(profile: str = "workstation", progress=None, cancel_event: threading.Event | None = None,
         on_finding=None, timeout: float = 180.0) -> AuditReport:
    if profile not in ("workstation", "server"):
        raise ValueError("Unsupported profile")
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 1 <= timeout <= 7200:
        raise ValueError("Assessment timeout must be between 1 and 7200 seconds")
    probe = Probe(cancel_event=cancel_event, timeout=timeout)
    report = AuditReport(profile=profile, inventory={})
    try:
        if progress:
            progress("Collecting hardware and host inventory…")
        inventory(probe, report.inventory)
        report.findings = hardening_checks(probe, profile, progress, on_finding=on_finding)
        probe.check_cancelled()
    except ProbeCancelled:
        report.cancelled = True
    if probe.cancel_reason:
        report.cancelled = True
        stopped = Finding("scan.incomplete", "Scanner", "Assessment stopped", "UNKNOWN", "info",
                          probe.cancel_reason + "; completed findings were retained",
                          "Unfinished controls were not evaluated. A partial report must not be treated as a complete baseline.")
        report.findings.append(stopped)
        if on_finding:
            on_finding(stopped)
    report.probe_errors = list(dict.fromkeys(probe.errors))
    report.incomplete = report.cancelled or bool(report.probe_errors) or any(f.status == "UNKNOWN" for f in report.findings)
    report.completed_utc = datetime.now(timezone.utc).isoformat()
    if progress:
        state = "Stopped" if report.cancelled else "Completed"
        progress(f"{state}: {len(report.findings)} controls; " + ("coverage limits recorded" if report.incomplete else "selected checks finished"))
    return report
