"""Bounded, metadata-only review of the original LinFo environment indicators."""
from __future__ import annotations
import os
from pathlib import Path
import platform
import re
import stat
from .models import Finding


def _row(ident, category, title, status, severity, summary, evidence="", recommendation="", reference=""):
    if len(evidence) > 1600:
        evidence = evidence[:1600] + "\n[Evidence shortened to 1,600 characters.]"
    return Finding(ident, category, title, status, severity, summary, evidence, recommendation, reference=reference)


def _complete(result):
    return result.ok and not any(getattr(result, flag, False) for flag in ("truncated", "timed_out", "cancelled"))


def path_entry_note(path: str, metadata=None, uid: int | None = None) -> tuple[bool, str]:
    """Use permission bits, not root's effective ability to write all files."""
    if path in {"", "."}:
        return True, "current directory in search path"
    if not os.path.isabs(path):
        return True, "relative search directory"
    if metadata is None:
        return False, "missing or inaccessible entry"
    if not stat.S_ISDIR(metadata.st_mode):
        return True, "not a directory"
    if metadata.st_mode & stat.S_IWOTH:
        return True, "world-writable directory"
    if metadata.st_mode & stat.S_IWGRP:
        return False, "group-writable; review membership"
    if metadata.st_uid == uid and uid != 0 and metadata.st_mode & stat.S_IWUSR:
        return False, "user-owned tools directory"
    return False, "no non-owner mode-bit writes"


def environment_findings(probe, profile):
    entries = os.environ["PATH"].split(":") if "PATH" in os.environ else []
    rows, risks, unavailable = [], 0, 0
    for path in entries[:80]:
        probe.check_cancelled()
        try:
            metadata = os.stat(path) if path else None
        except OSError:
            metadata = None
        risky, note = path_entry_note(path, metadata, os.geteuid())
        risks += int(risky)
        unavailable += int(metadata is None and path not in {"", "."})
        rows.append(f"{path or '<empty>'}: {note}")
    status = "WARN" if risks else "UNKNOWN" if unavailable or len(entries) > 80 else "INFO"
    yield _row("environment.path", "Environment", "Executable search path", status, "medium",
               f"{risks} risky PATH entries observed; this process's launch environment only",
               "\n".join(rows) + ("\nOnly the first 80 entries were evaluated." if len(entries) > 80 else "")
               + "\nPersonal tool directories are normal. ACLs and writable ancestor directories are not fully assessed.",
               "Review relative/current-directory entries and unintended write access.")
    keys = ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB", "RUBYLIB", "NODE_PATH", "GEM_PATH")
    present = [key for key in keys if os.environ.get(key)]
    yield _row("environment.loaders", "Environment", "Loader and language environment", "INFO", "low",
               f"{len(present)} relevant environment variables are set",
               ", ".join(present) or "None observed",
               "Variable values are omitted. These variables have legitimate development uses; presence alone is not an injection verdict.")


def process_indicator(name: str, arguments: str) -> bool:
    name = Path(name).name
    if name in {"nc", "netcat", "ncat", "socat"}:
        return True
    if name in {"sh", "bash", "dash", "zsh"} and re.search(r"/dev/(?:tcp|udp)/", arguments):
        return True
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?|perl", name):
        return bool(re.search(r"\bsocket(?:\.|\(|\s)|\bSocket\b", arguments))
    return False


def process_findings(probe, profile):
    result = probe.run("ps", "-eo", "pid=,uid=,comm=,args=")
    if not _complete(result):
        yield _row("process.review", "Processes", "Network utility process indicators", "UNKNOWN", "medium",
                   "Process collection unavailable or incomplete", result.error or "No complete process listing returned")
        return
    matches = []
    for line in result.out.splitlines():
        probe.check_cancelled()
        parts = line.strip().split(None, 3)
        if len(parts) >= 3 and process_indicator(parts[2], parts[3] if len(parts) > 3 else ""):
            matches.append(f"PID {parts[0]}, UID {parts[1]}, executable {parts[2]}")
    yield _row("process.review", "Processes", "Network utility process indicators", "WARN" if matches else "INFO", "medium",
               f"{len(matches)} processes match review heuristics",
               "\n".join(matches[:25]) + ("\nAdditional matching records omitted." if len(matches) > 25 else ""),
               "Command arguments are omitted. Diagnostic tools and legitimate development may match; these patterns do not detect all malicious processes.")


def kernel_metadata_findings(probe, profile):
    raw = probe.read("/proc/cpuinfo", 1048576)
    flags = set()
    if raw is not None:
        for line in raw.splitlines():
            if re.match(r"^(flags|Features)\s*:", line):
                flags.update(line.split(":", 1)[1].split())
    yield _row("kernel.cpu_capabilities", "Kernel", "CPU security capabilities", "INFO" if raw is not None else "UNKNOWN", "info",
               "x86 NX / SMEP / SMAP capability inventory",
               "; ".join(f"{name.upper()}: {'advertised' if name in flags else 'not advertised'}" for name in ("nx", "smep", "smap")) if raw is not None else "CPU flags unavailable",
               "CPU flags show advertised support, not active kernel enforcement. Other architectures use different mechanisms.")
    raw = probe.read(f"/boot/config-{platform.release()}", 1048576)
    keys = ("CONFIG_STACKPROTECTOR", "CONFIG_STACKPROTECTOR_STRONG", "CONFIG_RANDOMIZE_BASE", "CONFIG_MODULE_SIG", "CONFIG_MODULE_SIG_FORCE", "CONFIG_HARDENED_USERCOPY", "CONFIG_FORTIFY_SOURCE")
    rows = [line for line in (raw or "").splitlines() if any(line.startswith(key + "=") or line == f"# {key} is not set" for key in keys)]
    yield _row("kernel.build_options", "Kernel", "Kernel hardening build options", "INFO" if rows else "UNKNOWN", "info",
               "Matching kernel build configuration; runtime applicability must be checked separately",
               "\n".join(rows) or "Matching /boot kernel configuration is unavailable or contains no recognized entries")


def module_findings(probe, profile):
    raw = probe.read("/proc/modules")
    if raw is None:
        yield _row("kernel.module_signers", "Kernel", "Loaded module signer metadata", "UNKNOWN", "medium", "Loaded module list unavailable")
        return
    names = [line.split()[0] for line in raw.splitlines() if line.strip()]
    if not names:
        yield _row("kernel.module_signers", "Kernel", "Loaded module signer metadata", "INFO", "info", "No loadable modules visible", "Built-in drivers and modules outside the current namespace are not evaluated")
        return
    if not probe.which("modinfo"):
        yield _row("kernel.module_signers", "Kernel", "Loaded module signer metadata", "UNKNOWN", "medium", "modinfo is unavailable", f"{len(names)} loaded modules observed; signer metadata could not be inspected")
        return
    unsigned, unknown, signed = [], [], 0
    for name in names[:48]:
        probe.check_cancelled()
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            unknown.append("unrecognized module name")
            continue
        result = probe.run("modinfo", "-F", "signer", name, timeout=1.5)
        if not _complete(result):
            unknown.append(name)
        elif result.out.strip():
            signed += 1
        else:
            unsigned.append(name)
    status = "WARN" if unsigned else "UNKNOWN" if unknown or len(names) > 48 else "INFO"
    evidence = f"Inspected {min(48, len(names))}/{len(names)} modules; signer field present: {signed}.\n"
    evidence += "No signer metadata: " + (", ".join(unsigned) or "none observed")
    evidence += "\nUnavailable metadata: " + (", ".join(unknown) or "none")
    yield _row("kernel.module_signers", "Kernel", "Loaded module signer metadata", status, "medium",
               "Installed module metadata; not cryptographic verification of the loaded code", evidence,
               "Review expected third-party modules and enforced signature policy. Missing metadata does not prove malicious code.",
               "https://docs.kernel.org/admin-guide/module-signing.html")


def original_indicator_findings(probe, profile):
    for group in (environment_findings, process_findings, kernel_metadata_findings, module_findings):
        probe.check_cancelled()
        yield from group(probe, profile)
