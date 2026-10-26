"""Distribution package observations from local caches only.

This module never refreshes repositories, installs updates, or starts services.
An empty or stale cache cannot establish that a machine is fully patched.
Finding IDs remain compatible with the existing report and management layers.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Iterator

from .management import detect_platform
from .models import Finding
from .probe import Probe, Result


CACHED_COMMANDS: dict[str, tuple[str, ...]] = {
    "apt": ("apt", "list", "--upgradable"),
    # check-upgrade works with DNF4 and DNF5. Disable plugins for this query;
    # plugin-provided repositories can consequently be absent from the view.
    "dnf": ("dnf", "--cacheonly", "--setopt=plugins=0", "--color=never", "--quiet", "check-upgrade"),
    "yum": ("yum", "--cacheonly", "--noplugins", "--color=never", "--quiet", "check-update"),
    "zypper": ("zypper", "--no-refresh", "--non-interactive", "--xmlout", "list-updates"),
    "pacman": ("pacman", "-Qu", "--color", "never"),
}
REFERENCES = {
    "apt": "https://manpages.debian.org/trixie/apt/apt.8.en.html",
    "dnf": "https://dnf5.readthedocs.io/en/latest/commands/check-upgrade.8.html",
    "yum": "https://dnf.readthedocs.io/en/latest/command_ref.html#check-update-command",
    "zypper": "https://manpages.opensuse.org/Tumbleweed/zypper/zypper.8.en.html",
    "pacman": "https://man.archlinux.org/man/pacman.8.en.html",
}
CACHE_SCOPE = (
    "Local cached repository metadata only; cache freshness/completeness and security advisory coverage are not verified. "
    "No repository refresh, downloads or package changes were requested. Zero candidates is not proof that the system is up to date."
)


def _finding(ident: str, title: str, status: str, summary: str,
             evidence: str = "", recommendation: str = "", reference: str = "") -> Finding:
    return Finding(ident, "Packages", title, status, "medium", summary,
                   evidence[:1600], recommendation, reference=reference)


def _incomplete(result: Result) -> bool:
    return any(bool(getattr(result, key, False)) for key in ("timed_out", "truncated", "missing", "cancelled"))


def _diagnostic(result: Result) -> str:
    """Keep partial stdout out of failure evidence; strip URL credentials."""
    notes = [f"Exit code: {result.returncode if result.returncode is not None else 'unavailable'}."]
    for flag, label in (("timed_out", "Command time limit reached"), ("truncated", "Output limit reached"),
                        ("missing", "Command unavailable"), ("cancelled", "Command cancelled")):
        if getattr(result, flag, False):
            notes.append(label + ".")
    if result.error:
        error = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@", r"\1[credentials redacted]@", result.error)
        notes.append(error[:350])
    return " ".join(notes)


def _cache_error(text: str) -> bool:
    return bool(re.search(
        r"(?im)(?:^\s*(?:error:|e:)\s|permission denied|failed to (?:download|load|read|synchronize)|"
        r"no (?:cached?|enabled repositor|repositories available)|cache-only enabled but|"
        r"(?:ignoring|skipping) repositor|(?:cannot|could not) (?:load|read|open)|"
        r"repository .* (?:not cached|is invalid))", text))


def parse_apt_updates(text: str) -> tuple[list[str], bool]:
    """Parse the known list format; unfamiliar output never means zero."""
    packages: list[str] = []
    recognized = False
    unexpected = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Listing..."):
            recognized = True
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9+_.:-]*)/\S+\s+\S+\s+\S+\s+\[upgradable from: .+\]$", line)
        if match:
            recognized = True
            packages.append(match.group(1))
        elif not line.startswith("N: "):
            unexpected = True
    return list(dict.fromkeys(packages)), recognized and not unexpected


def parse_rpm_updates(text: str) -> list[str]:
    """Names are optional evidence; the documented exit code is authoritative."""
    architecture = r"(?:noarch|x86_64|i[3-6]86|aarch64|arm\w*|ppc\w*|s390\w*|riscv\w*|loongarch\w*)"
    pattern = re.compile(r"^\s*([A-Za-z0-9_+.-]+\." + architecture + r")\s+(\S+)\s+(\S+)\s*$")
    packages = []
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            packages.append(match.group(1))
    return list(dict.fromkeys(packages))


def parse_pacman_updates(text: str) -> tuple[list[str], bool]:
    packages = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.match(r"^(\S+)\s+\S+\s+->\s+\S+\s*$", line)
        if not match:
            return [], False
        packages.append(match.group(1))
    return list(dict.fromkeys(packages)), True


def parse_zypper_updates(text: str) -> tuple[list[str], bool]:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        return [], False
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return [], False
    tags = lambda element: element.tag.rsplit("}", 1)[-1]
    if tags(root) != "stream":
        return [], False
    if any(tags(node) == "error" or (tags(node) == "message" and node.get("type") == "error") for node in root.iter()):
        return [], False
    lists = [node for node in root.iter() if tags(node) == "update-list"]
    if not lists:
        return [], False
    packages = []
    for update_list in lists:
        for node in update_list.iter():
            if tags(node) != "update":
                continue
            if node.get("kind", "package") != "package" or not node.get("name"):
                return [], False
            name = node.get("name", "")
            if node.get("arch"):
                name += "." + node.get("arch", "")
            packages.append(name)
    return list(dict.fromkeys(packages)), True


def cached_update_finding(probe: Probe, manager: str | None) -> Finding:
    title = "Cached package updates"
    advice = "Refresh metadata through the normal maintenance workflow, then review and apply appropriate updates."
    if manager not in CACHED_COMMANDS:
        return _finding("package.pending", title, "UNKNOWN", "No supported package manager was detected.",
                        "Unsupported does not mean zero updates.", advice)
    result = probe.run(*CACHED_COMMANDS[manager], timeout=18)
    if _incomplete(result):
        return _finding("package.pending", title, "UNKNOWN", f"{manager.upper()} cached query was incomplete.",
                        _diagnostic(result), advice, REFERENCES[manager])
    expected = result.returncode == 0
    if manager in {"dnf", "yum"} and result.returncode == 100:
        expected = True
    if manager == "pacman" and result.returncode == 1 and not result.out.strip() and not result.error.strip():
        expected = True
    if not expected or _cache_error(result.error + "\n" + result.out):
        return _finding("package.pending", title, "UNKNOWN", f"{manager.upper()} cached query could not establish update status.",
                        _diagnostic(result), advice, REFERENCES[manager])
    valid = True
    if manager == "apt":
        packages, valid = parse_apt_updates(result.out)
        pending = bool(packages)
    elif manager == "pacman":
        packages, valid = parse_pacman_updates(result.out)
        pending = bool(packages)
        # Exit 1 with output or diagnostics is not the documented empty query.
        if result.returncode == 1 and (result.out.strip() or result.error.strip()):
            valid = False
    elif manager == "zypper":
        packages, valid = parse_zypper_updates(result.out)
        pending = bool(packages)
    else:
        packages = parse_rpm_updates(result.out)
        pending = result.returncode == 100
        if result.returncode == 0 and packages:
            valid = False  # A contradictory result is not a clean bill of health.
    if not valid:
        return _finding("package.pending", title, "UNKNOWN", "Package-manager output could not be interpreted reliably.",
                        f"Manager: {manager}. " + _diagnostic(result), advice, REFERENCES[manager])
    if pending:
        if manager in {"dnf", "yum"}:
            summary = f"{manager.upper()} reports update candidates in cached metadata (exit 100)."
        else:
            summary = f"{len(packages)} package update candidate(s) in cached metadata."
        status = "WARN"
    else:
        summary = "No update candidates reported by the cached query; patch completeness is unverified."
        status = "INFO"
    evidence = f"Manager: {manager.upper()}. {CACHE_SCOPE}"
    if manager in {"dnf", "yum"}:
        evidence += " Plugins are disabled for this read-only query; plugin-provided repositories may be absent."
    if packages:
        evidence += f"\nParsed package names ({min(len(packages), 12)} shown; {len(packages)} parsed): " + ", ".join(packages[:12])
    elif pending:
        evidence += "\nPackage-list format was not recognized; no exact package count is asserted."
    return _finding("package.pending", title, status, summary, evidence, advice, REFERENCES[manager])


def parse_apt_periodic(text: str) -> dict[str, str]:
    values = {}
    for name in ("Enable", "Unattended-Upgrade", "Update-Package-Lists"):
        match = re.search(r'^APT::Periodic::' + re.escape(name) + r'\s+"([^"\n]*)";', text, re.MULTILINE)
        if match:
            values[name] = match.group(1)
    return values


def apt_automatic_finding(probe: Probe) -> Finding:
    """Inspect effective APT settings, not just one distro drop-in file."""
    installed = probe.run("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
    config = probe.run("apt-config", "dump")
    package_present = installed.ok and not _incomplete(installed) and installed.out.strip() == "install ok installed"
    package_absent = not _incomplete(installed) and (
        (installed.ok and installed.out.strip() in {"deinstall ok config-files", "unknown ok not-installed", "purge ok not-installed"})
        or (installed.returncode == 1 and "no packages found matching" in installed.error.lower())
    )
    values = parse_apt_periodic(config.out) if config.ok and not _incomplete(config) else {}
    package_label = "installed" if package_present else "not installed" if package_absent else "unknown"
    evidence = f"unattended-upgrades: {package_label}."
    if package_label == "unknown":
        evidence += " " + _diagnostic(installed)
    for key, value in values.items():
        evidence += f"\nAPT::Periodic::{key} = {value}"
    evidence += ("\nEffective apt-config values are checked across configuration files. "
                 "Allowed origins, exclusions, reboots, actual applied updates, and alternative maintenance schedules are not verified.")
    advice = "Review unattended-upgrades origins, timers/cron, successful runs and reboot policy for this host."
    if not config.ok or _incomplete(config) or package_label == "unknown":
        return _finding("package.automatic", "Automatic package upgrades", "UNKNOWN",
                        "Package installation or effective APT configuration could not be verified.",
                        evidence + "\nAPT configuration: " + _diagnostic(config), advice)
    interval = values.get("Unattended-Upgrade", "0")
    enabled = values.get("Enable", "1") != "0" and (interval == "always" or interval.isdecimal() and int(interval) > 0)
    if not package_present or not enabled:
        return _finding("package.automatic", "Automatic package upgrades", "WARN",
                        "The standard unattended-upgrades configuration is not enabled or its package is absent.", evidence, advice)
    timer = probe.run("systemctl", "show", "apt-daily-upgrade.timer", "--no-pager",
                      "--property=LoadState,ActiveState,UnitFileState")
    state = dict(line.split("=", 1) for line in timer.out.splitlines() if "=" in line) if timer.ok and not _incomplete(timer) else {}
    if state.get("LoadState") == "loaded" and state.get("ActiveState") == "active":
        status = "PASS"
        summary = "Unattended upgrades are configured and the standard systemd timer is active."
        evidence += "\napt-daily-upgrade.timer: active; enablement=" + state.get("UnitFileState", "unknown")
        evidence += ". Timer activity does not establish a successful update transaction."
    else:
        status = "INFO"
        summary = "Unattended upgrades are configured; the standard active timer was not confirmed."
        evidence += "\nThe host may use cron or another scheduler. " + _diagnostic(timer)
    return _finding("package.automatic", "Automatic package upgrades", status, summary, evidence, advice)


def package_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    platform = detect_platform(os_release=probe.read("/etc/os-release") or "", which=probe.which)
    yield cached_update_finding(probe, platform.package_manager)
    if platform.package_manager == "apt":
        yield apt_automatic_finding(probe)
