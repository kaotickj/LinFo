"""Assemble a local, read-only assessment."""
from __future__ import annotations
import json
import os
import platform
import socket
from .checks import hardening_checks
from .models import AuditReport
from .probe import Probe
from .management import detect_platform


def os_pretty() -> str:
    data = Probe.read("/etc/os-release") or ""
    for line in data.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.system()


def inventory(probe: Probe) -> dict:
    platform_info = detect_platform()
    info = {
        "operating_system": os_pretty(),
        "distribution_id": platform_info.distro_id,
        "package_manager": platform_info.package_manager or "Unsupported/undetected",
        "admin_group": platform_info.admin_group,
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "root_privileges": os.geteuid() == 0,
        "desktop": os.environ.get("XDG_CURRENT_DESKTOP", "Not detected"),
    }
    mem = Probe.read("/proc/meminfo", 2000) or ""
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


def scan(profile: str = "workstation", progress=None) -> AuditReport:
    if profile not in ("workstation", "server"):
        raise ValueError("Unsupported profile")
    probe = Probe()
    if progress:
        progress("Collecting hardware and host inventory…")
    inv = inventory(probe)
    findings = hardening_checks(probe, profile, progress)
    if progress:
        progress(f"Completed {len(findings)} controls")
    return AuditReport(profile=profile, inventory=inv, findings=findings)
