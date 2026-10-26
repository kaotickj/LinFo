"""Read-only local security controls. A missing tool or denied access is UNKNOWN, not PASS."""
from __future__ import annotations
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
from typing import Callable, Iterator
from .models import Finding
from .probe import Probe, ProbeCancelled
from .management import detect_platform
from .extra_checks import original_indicator_findings

# Restrict auto-remediation to reversible, host-local sysctl changes.
ACTIONS: dict[str, dict[str, str]] = {
    "aslr": {"kernel.randomize_va_space": "2"},
    "protected_links": {"fs.protected_hardlinks": "1", "fs.protected_symlinks": "1"},
    "ptrace": {"kernel.yama.ptrace_scope": "1"},
    "icmp_redirects": {"net.ipv4.conf.all.accept_redirects": "0",
                       "net.ipv4.conf.default.accept_redirects": "0",
                       "net.ipv4.conf.all.send_redirects": "0",
                       "net.ipv4.conf.default.send_redirects": "0"},
    "source_route": {"net.ipv4.conf.all.accept_source_route": "0",
                     "net.ipv4.conf.default.accept_source_route": "0"},
}
ACTION_LABELS = {
    "aslr": "Enable full address-space layout randomization (ASLR)",
    "protected_links": "Enable protected symbolic/hard links",
    "ptrace": "Restrict ptrace to parent-child debugging relationships (may affect debuggers)",
    "icmp_redirects": "Disable IPv4 ICMP redirect acceptance and sending",
    "source_route": "Reject IPv4 source-routed packets",
}


def finding(id: str, category: str, title: str, status: str, severity: str,
            summary: str, evidence: str = "", recommendation: str = "",
            action_id: str | None = None, reference: str = "") -> Finding:
    if len(evidence) > 1600:
        evidence = evidence[:1600] + "\n[Evidence shortened to 1,600 characters.]"
    return Finding(id, category, title, status, severity, summary, evidence,
                   recommendation, action_id, reference)


def _complete(result) -> bool:
    """Keep complete evidence distinct from partial stdout and command failures."""
    return (result.ok and not getattr(result, "truncated", False)
            and not getattr(result, "timed_out", False)
            and not getattr(result, "cancelled", False))


def command_service(probe: Probe, unit: str) -> str | None:
    if not probe.which("systemctl"):
        return None
    r = probe.run("systemctl", "is-active", unit)
    if any(getattr(r, key, False) for key in ("truncated", "timed_out", "cancelled")):
        return None
    state = r.out.strip()
    if (_complete(r) or r.returncode == 3) and state in {"active", "inactive", "failed", "activating", "deactivating"}:
        return state
    return None


def sysctl_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    controls = [
        ("aslr", "Process ASLR", "kernel.randomize_va_space", "2", "high", "aslr"),
        ("hardlinks", "Hard-link protection", "fs.protected_hardlinks", "1", "medium", "protected_links"),
        ("symlinks", "Symlink protection", "fs.protected_symlinks", "1", "medium", "protected_links"),
        ("ptrace", "Yama ptrace restrictions", "kernel.yama.ptrace_scope", "1", "medium", "ptrace"),
        ("redirect_all", "IPv4 redirect acceptance (all)", "net.ipv4.conf.all.accept_redirects", "0", "medium", "icmp_redirects"),
        ("redirect_default", "IPv4 redirect acceptance (default)", "net.ipv4.conf.default.accept_redirects", "0", "medium", "icmp_redirects"),
        ("send_all", "IPv4 redirect sending (all)", "net.ipv4.conf.all.send_redirects", "0", "medium", "icmp_redirects"),
        ("send_default", "IPv4 redirect sending (default)", "net.ipv4.conf.default.send_redirects", "0", "medium", "icmp_redirects"),
        ("source_all", "IPv4 source routing (all)", "net.ipv4.conf.all.accept_source_route", "0", "medium", "source_route"),
        ("source_default", "IPv4 source routing (default)", "net.ipv4.conf.default.accept_source_route", "0", "medium", "source_route"),
    ]
    for ident, title, key, wanted, severity, action in controls:
        got = probe.sysctl(key)
        if got is None:
            yield finding("sysctl." + ident, "Kernel", title, "UNKNOWN", severity,
                          "Kernel interface unavailable or not readable", key)
            continue
        if not re.fullmatch(r"-?\d+", got) or (ident == "ptrace" and got not in {"0", "1", "2", "3"}):
            yield finding("sysctl." + ident, "Kernel", title, "UNKNOWN", severity,
                          "Unrecognized runtime value; no automatic change proposed", f"{key} = {got}")
            continue
        passed = (got == wanted or (ident == "ptrace" and got in {"2", "3"}))
        detail = f"{key} = {got}; desired: {wanted}"
        if ident == "ptrace":
            modes = {"0": "classic ptrace permissions", "1": "restricted ptrace with relationship/capability exceptions",
                     "2": "CAP_SYS_PTRACE required", "3": "ptrace attach/TRACEME disabled; cannot relax until reboot"}
            detail = f"{key} = {got}: {modes[got]}; restricted values: 1, 2 or 3"
        yield finding("sysctl." + ident, "Kernel", title, "PASS" if passed else "WARN", severity,
                      "Effective runtime kernel setting", detail,
                      "Review workload compatibility before changing kernel sysctls.",
                      None if passed else action,
                      "https://docs.kernel.org/admin-guide/LSM/Yama.html" if ident == "ptrace" else "https://docs.kernel.org/admin-guide/sysctl/kernel.html")


def account_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    try:
        entries = pwd.getpwall()
    except OSError:
        entries = []
    if not entries:
        yield finding("account.uid0", "Accounts", "Additional UID 0 accounts", "UNKNOWN", "high", "Cannot inspect local account database")
    else:
        extra = [x.pw_name for x in entries if x.pw_uid == 0 and x.pw_name != "root"]
        yield finding("account.uid0", "Accounts", "Additional UID 0 accounts", "FAIL" if extra else "PASS", "high",
                      "Non-root usernames mapped to superuser UID", ", ".join(extra) if extra else "None",
                      "Investigate each additional UID 0 account. Do not delete accounts without confirming purpose.")
        interactive = [x.pw_name for x in entries if x.pw_uid >= 1000 and x.pw_shell not in
                       {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}]
        yield finding("account.interactive", "Accounts", "Interactive local accounts", "INFO", "info",
                      "Review approved interactive users", ", ".join(interactive[:35]) or "None")
    try:
        members = {g.gr_name: g.gr_mem for g in grp.getgrall() if g.gr_name in ("sudo", "wheel")}
        yield finding("account.admins", "Accounts", "Administrative groups", "INFO", "info",
                      "Inspect members and effective group membership separately", str(members)[:1000])
    except OSError:
        pass
    for path, label in [("/etc/shadow", "Shadow password database"),
                        ("/etc/gshadow", "Shadow group database"),
                        ("/etc/passwd", "Local account database")]:
        try:
            metadata = os.stat(path, follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISREG(metadata.st_mode):
                yield finding("file." + Path(path).name, "Permissions", label, "UNKNOWN", "high",
                              "Expected regular account file; target permissions not evaluated", f"{path}: {stat.filemode(metadata.st_mode)}")
                continue
            bad = metadata.st_uid != 0 or bool(mode & 0o027)
            # /etc/passwd is expected to be world-readable, but never world-writable.
            if path == "/etc/passwd":
                bad = metadata.st_uid != 0 or bool(mode & 0o022)
            yield finding("file." + Path(path).name, "Permissions", label,
                          "FAIL" if bad else "PASS", "high", "Check sensitive account file permissions",
                          f"{path}: {mode:04o}; owner UID {metadata.st_uid}; group GID {metadata.st_gid}. ACLs are not assessed.",
                          "Review owner/mode against your distribution's policy. Never apply generic chmod blindly.")
        except OSError as exc:
            yield finding("file." + Path(path).name, "Permissions", label, "UNKNOWN", "medium",
                          "File not accessible", str(exc))
    for path in ("/tmp", "/var/tmp", "/dev/shm"):
        try:
            mode = os.stat(path).st_mode
            if not stat.S_ISDIR(mode):
                status = "UNKNOWN"
            elif mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
                status = "FAIL"
            else:
                status = "PASS"
            yield finding("file.temp." + path.strip("/").replace("/", "_"), "Permissions",
                          f"Sticky bit on {path}", status, "high", "World-writable shared directories need sticky-bit protection",
                          f"{path}: {stat.S_IMODE(mode):04o}", "Set the sticky bit after checking intended directory use.")
        except OSError as exc:
            yield finding("file.temp." + path.strip("/").replace("/", "_"), "Permissions",
                          f"Sticky bit on {path}", "UNKNOWN", "high", "Directory metadata unavailable", str(exc))


def ssh_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    sshd = probe.which("sshd")
    if not sshd:
        yield finding("ssh.available", "SSH", "SSH server", "INFO", "info", "sshd binary not found; no SSH server configuration evaluated")
        return
    active = command_service(probe, "ssh.service") == "active" or command_service(probe, "sshd.service") == "active"
    yield finding("ssh.service", "SSH", "SSH service", "INFO", "info", "Service state is inventory, not a vulnerability",
                  "active" if active else "not confirmed active")
    r = probe.run(sshd, "-T", timeout=10)
    if not _complete(r):
        yield finding("ssh.config", "SSH", "Effective SSH configuration", "UNKNOWN", "medium",
                      "Cannot obtain effective global sshd configuration; may require root",
                      r.error or "Effective configuration output was incomplete.", "Use 'sudo sshd -T' and validate relevant Match contexts.")
        return
    effective = dict(line.split(None, 1) for line in r.out.splitlines() if " " in line)
    rules = [
        ("permitrootlogin", {"no"}, "Root SSH login", "high", "Prefer non-root administrative accounts and tested sudo access before changing."),
        ("permitemptypasswords", {"no"}, "Empty SSH passwords", "high", "Never permit empty SSH passwords."),
        ("passwordauthentication", {"no"}, "SSH password authentication", "medium", "Key-only login is suitable only after validating working keys and recovery access."),
    ]
    for key, allowed, title, severity, advice in rules:
        value = effective.get(key)
        if value is None:
            status = "UNKNOWN"
        elif value.lower() in allowed:
            status = "PASS"
        elif key == "passwordauthentication":
            status = "WARN"
        else:
            status = "WARN"
        if key == "passwordauthentication" and profile == "workstation":
            severity = "low"
        yield finding("ssh." + key, "SSH", title, status, severity,
                      "Global sshd -T value; Match blocks may alter per-connection settings",
                      f"{key} = {value or 'not available'}", advice)
    sshconf = Path("/etc/ssh/sshd_config")
    if sshconf.exists():
        try:
            metadata = sshconf.stat()
            mode = metadata.st_mode
            bad = metadata.st_uid != 0 or not stat.S_ISREG(mode) or bool(mode & 0o022)
            yield finding("ssh.config_perm", "SSH", "SSH configuration writability", "FAIL" if bad else "PASS", "high",
                          "Unprivileged writes to SSH configuration must be prohibited",
                          f"{sshconf}: {stat.S_IMODE(mode):04o}; owner UID {metadata.st_uid}; included files are not all evaluated")
        except OSError as exc:
            yield finding("ssh.config_perm", "SSH", "SSH configuration writability", "UNKNOWN", "high",
                          "Configuration metadata unavailable", str(exc))


def firewall_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    # Managers can be active with permissive policies. Inspect each available
    # backend, including legacy iptables, before making a scoped observation.
    notes, failures = [], []
    configured, inspected = False, 0
    if probe.which("ufw"):
        ufw = probe.run("ufw", "status")
        if _complete(ufw):
            state = re.search(r"^Status:\s+(active|inactive)\b", ufw.out, re.M | re.I)
            notes.append("UFW manager: " + (state.group(1).lower() if state else "unrecognized status"))
        else:
            failures.append("UFW status unavailable: " + ufw.error[:150])
    if probe.which("firewall-cmd"):
        fw = probe.run("firewall-cmd", "--state")
        if _complete(fw) or (fw.returncode == 252 and not any(getattr(fw, flag, False) for flag in ("timed_out", "truncated", "cancelled"))):
            notes.append("firewalld manager: " + fw.out.strip()[:80])
        else:
            failures.append("firewalld state unavailable: " + fw.error[:150])
    if probe.which("nft"):
        r = probe.run("nft", "-j", "-n", "list", "ruleset")
        if _complete(r):
            try:
                data = json.loads(r.out)
                if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
                    raise ValueError("Unexpected ruleset structure")
                objects = data["nftables"]
                chains = [item["chain"] for item in objects if isinstance(item, dict) and isinstance(item.get("chain"), dict)]
                rules = [item["rule"] for item in objects if isinstance(item, dict) and isinstance(item.get("rule"), dict)]
                inbound = [chain for chain in chains if chain.get("hook") in {"input", "ingress"}]
                configured |= bool(rules or any(chain.get("policy") == "drop" for chain in inbound))
                inspected += 1
                notes.append(f"nftables: {len(rules)} rule objects; {len(inbound)} input/ingress base chains")
                for chain in inbound[:8]:
                    notes.append(f"  {chain.get('family', '?')}/{chain.get('table', '?')}/{chain.get('name', '?')}: policy {chain.get('policy', 'unspecified')}")
            except (ValueError, TypeError, AttributeError):
                failures.append("nftables output could not be interpreted completely")
        else:
            failures.append("nftables rules unavailable: " + (r.error or "incomplete output")[:150])
    for executable, label in (("iptables", "IPv4"), ("ip6tables", "IPv6")):
        if not probe.which(executable):
            continue
        r = probe.run(executable, "-S")
        if not _complete(r):
            failures.append(label + " filter unavailable: " + (r.error or "incomplete output")[:150])
            continue
        rules = [line for line in r.out.splitlines() if line.startswith("-A ")]
        policies = {}
        for line in r.out.splitlines():
            tokens = line.split()
            if len(tokens) == 3 and tokens[0] == "-P":
                policies[tokens[1]] = tokens[2]
        if not policies:
            failures.append(label + " filter policy could not be interpreted")
            continue
        inspected += 1
        configured |= bool(rules or policies.get("INPUT") == "DROP")
        notes.append(f"{label} iptables: {len(rules)} filter rules; INPUT={policies.get('INPUT', 'unknown')}, FORWARD={policies.get('FORWARD', 'unknown')}, OUTPUT={policies.get('OUTPUT', 'unknown')}")
    if failures or not inspected:
        status, summary = "UNKNOWN", "Firewall policy inspection is incomplete"
    elif configured:
        status, summary = "WARN", "Rules or restrictive policies observed; effective coverage needs review"
    else:
        status, summary = "WARN", "No filtering demonstrated by the inspected rules and policies"
    evidence = "\n".join(notes + failures)
    evidence += "\nManager activity or rule presence alone does not prove protection. Current network namespace only; nft and iptables views may overlap."
    if not inspected:
        evidence += " No complete packet-filter ruleset was available."
    yield finding("network.firewall", "Network", "Host firewall", status, "high", summary, evidence,
                  "Review IPv4/IPv6 input policies, rule order and reachable services. Other namespaces, backends and upstream filters are outside this check.",
                  reference="https://netfilter.org/projects/nftables/manpage.html")


def network_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    r = probe.run("ss", "-H", "-lntu")
    if not _complete(r):
        yield finding("network.listeners", "Network", "Listening network sockets", "UNKNOWN", "medium",
                      "Socket inventory is unavailable or incomplete", r.error)
        yield finding("network.exposed", "Network", "Sensitive services listening on all interfaces", "UNKNOWN", "high",
                      "Cannot assess wildcard listeners from incomplete socket output", r.error)
        return
    lines = r.out.splitlines()
    yield finding("network.listeners", "Network", "Listening TCP/UDP endpoints", "INFO", "info",
                  "Inventory; include listeners not just TCP LISTEN", "\n".join(lines[:18]) + (f"\n... ({len(lines)} total)" if len(lines)>18 else ""))
    flagged, unparsed = [], 0
    sensitive_ports = {21, 23, 111, 139, 445, 3306, 5432, 5900, 6379, 9200, 11211, 27017}
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            if line.strip():
                unparsed += 1
            continue
        addr = fields[4]
        try:
            port = int(addr.rsplit(":", 1)[-1])
        except ValueError:
            unparsed += 1
            continue
        if port in sensitive_ports and (addr.startswith("0.0.0.0:") or addr.startswith("[::]:") or addr.startswith("*:") or addr.startswith(":::") ):
            flagged.append(addr)
    yield finding("network.exposed", "Network", "Sensitive services listening on all interfaces",
                  "WARN" if flagged else "UNKNOWN" if unparsed else "PASS", "high", "Selected wildcard-bound service ports; listener state does not establish remote reachability",
                  ", ".join(flagged[:25]) or "None of the selected ports exposed on wildcard addresses",
                  "Some socket rows could not be parsed." if unparsed else "Bind services to trusted addresses and verify firewall rules where appropriate.")


def access_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    for unit, label, severity in [("auditd.service", "Audit daemon", "medium"),
                                  ("fail2ban.service", "Fail2ban intrusion prevention", "low")]:
        value = command_service(probe, unit)
        if value is None:
            status = "UNKNOWN"
        elif value == "active":
            status = "PASS"
        else:
            status = "WARN"
        yield finding("svc." + unit, "Monitoring", label, status, severity,
                      "Not every deployment requires this specific product", f"State: {value or 'unknown'}",
                      "Consider this control based on your threat model and existing telemetry.")
    aide = probe.which("aide") or Path("/etc/aide/aide.conf").exists() or Path("/etc/aide.conf").exists()
    yield finding("monitor.aide", "Monitoring", "File integrity monitoring", "INFO", "low",
                  "AIDE presence does not confirm a current baseline or scheduled scans", "AIDE detected" if aide else "AIDE not detected",
                  "Consider a baseline and recurring integrity checks on high-trust systems.")
    if probe.which("systemctl"):
        for unit in ("telnet.socket", "rsh.socket", "rexec.socket"):
            service = command_service(probe, unit)
            yield finding("legacy." + unit, "Services", f"Legacy service {unit}",
                          "FAIL" if service == "active" else ("PASS" if service == "inactive" else "UNKNOWN"),
                          "high", "Legacy remote login should not be exposed",
                          f"State: {service or 'unknown'}", "Investigate and disable if not explicitly required.")


def package_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    # Preserve public finding IDs and management actions while keeping distro
    # query parsing isolated from unrelated security checks.
    from .package_updates import package_findings as collect_packages
    yield from collect_packages(probe, profile)


def integrity_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    for key, label in (("/proc/sys/kernel/kptr_restrict", "Kernel pointer exposure"),
                       ("/proc/sys/kernel/dmesg_restrict", "Kernel log access")):
        data = probe.read(key, 80)
        if data is None:
            status = "UNKNOWN"
        else:
            allowed = {"0", "1", "2"} if key.endswith("kptr_restrict") else {"0", "1"}
            status = "UNKNOWN" if data.strip() not in allowed else "WARN" if data.strip() == "0" else "PASS"
        yield finding("kernel." + key.rsplit("/", 1)[-1], "Kernel", label, status, "low",
                      "Kernel diagnostic visibility may be intentionally enabled for troubleshooting",
                      f"{key} = {data.strip() if data is not None else 'unknown'}")
    # LSM may be active even if aa-status/getenforce is not available.
    lsm = probe.read("/sys/kernel/security/lsm", 500)
    aa = probe.read("/sys/module/apparmor/parameters/enabled", 50)
    sel = probe.read("/sys/fs/selinux/enforce", 20)
    profiles = probe.read("/sys/kernel/security/apparmor/profiles") if aa is not None and aa.strip().upper() == "Y" else None
    enforcing = sum(line.rstrip().endswith("(enforce)") for line in (profiles or "").splitlines())
    enabled = (sel is not None and sel.strip() == "1") or enforcing > 0
    if enabled:
        mac_status, mac_summary = "PASS", "SELinux enforcing or AppArmor enforce-mode profiles observed; application coverage is separate"
    elif aa is not None and aa.strip().upper() == "Y" and profiles is None:
        mac_status, mac_summary = "UNKNOWN", "AppArmor enabled, but enforcing profile state could not be inspected"
    elif profiles is not None or (sel is not None and sel.strip() == "0") or lsm:
        mac_status, mac_summary = "WARN", "No enforcing SELinux/AppArmor policy demonstrated by available runtime data"
    else:
        mac_status, mac_summary = "UNKNOWN", "Mandatory access control runtime state unavailable"
    yield finding("kernel.lsm", "Kernel", "Mandatory access control", mac_status, "medium", mac_summary,
                  f"LSM: {(lsm or 'unavailable').strip()}; AppArmor enabled: {(aa or 'unknown').strip()}; enforce-mode profiles: {enforcing if profiles is not None else 'unavailable'}; SELinux enforce: {(sel or 'unknown').strip()}",
                  "Inspect the chosen LSM and application confinement policy, not just module presence.")
    for path in ("/tmp", "/var/tmp"):
        r = probe.run("findmnt", "-n", "-o", "OPTIONS", "-T", path) if probe.which("findmnt") else None
        if r and _complete(r):
            opts = set(r.out.strip().split(","))
            yield finding("mount." + path.strip("/"), "Filesystems", f"Filesystem options for {path}", "INFO", "low",
                          "Mount options depend on workload and partition layout",
                          ", ".join(sorted(opts & {"rw", "ro", "noexec", "nosuid", "nodev", "relatime", "noatime"})) + "; other options omitted",
                          "Consider noexec/nosuid/nodev only after compatibility review.")
        else:
            yield finding("mount." + path.strip("/"), "Filesystems", f"Filesystem options for {path}", "UNKNOWN", "low",
                          "Mount options unavailable", r.error if r else "findmnt not available")
    # Report count only, do not dump every path or collect sensitive contents.
    paths = [p for p in ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin") if Path(p).is_dir()]
    if paths and probe.which("find"):
        r = probe.run("find", *paths, "-xdev", "-maxdepth", "4", "-type", "f", "-perm", "/4000", "-print", timeout=18)
        if _complete(r):
            entries = [p for p in r.out.splitlines() if p]
            yield finding("file.suid", "Permissions", "SUID executable inventory", "INFO", "medium",
                          "SUID is not by itself a vulnerability. Compare a saved baseline and investigate unexpected changes.",
                          f"{len(entries)} SUID files observed in standard binary directories, within depth 4 and each filesystem. Symlinked directories are not followed.")
        else:
            yield finding("file.suid", "Permissions", "SUID executable inventory", "UNKNOWN", "medium",
                          "Incomplete scan", r.error)
    else:
        yield finding("file.suid", "Permissions", "SUID executable inventory", "UNKNOWN", "medium", "find unavailable")
    for path in ("/etc", "/usr/local/bin", "/usr/local/sbin"):
        if not Path(path).is_dir() or not probe.which("find"):
            continue
        r = probe.run("find", path, "-xdev", "-maxdepth", "6", "-type", "f", "-perm", "/0002", "-print", timeout=12)
        if _complete(r):
            files = r.out.splitlines()
            yield finding("file.worldwrite." + path.strip("/").replace("/", "_"), "Permissions",
                          f"World-writable files in {path}", "FAIL" if files else "PASS", "high",
                          "Other-write bit assessment within depth 6 on this filesystem", f"{len(files)} file(s): " + ", ".join(files[:5]),
                          "Review ownership and purpose before tightening permissions.")
        else:
            yield finding("file.worldwrite." + path.strip("/").replace("/", "_"), "Permissions",
                          f"World-writable files in {path}", "UNKNOWN", "medium", "Scan incomplete", r.error)


def hardening_checks(probe: Probe, profile: str, progress: Callable[[str], None] | None = None,
                     on_finding: Callable[[Finding], None] | None = None) -> list[Finding]:
    categories = [sysctl_findings, account_findings, ssh_findings, firewall_findings,
                  network_findings, access_findings, package_findings, integrity_findings, extra_findings,
                  original_indicator_findings]
    out: list[Finding] = []
    for group in categories:
        try:
            probe.check_cancelled()
            if progress:
                progress(f"Running {group.__name__.replace('_findings', '')} checks…")
            for row in group(probe, profile):
                out.append(row)
                if on_finding:
                    on_finding(row)
                probe.check_cancelled()
        except ProbeCancelled:
            break
        except Exception as exc:
            # Partial results remain useful, unexpected probe failures must not be counted as PASS.
            row = finding("error." + group.__name__, "Scanner", "Scanner module error", "UNKNOWN", "medium",
                          "Module failed; checks in this category may be incomplete", f"{type(exc).__name__}: {exc}")
            out.append(row)
            if on_finding:
                on_finding(row)
    order = {"FAIL": 0, "WARN": 1, "UNKNOWN": 2, "PASS": 3, "INFO": 4}
    return sorted(out, key=lambda f: (order.get(f.status, 5), f.category, f.title))


def extra_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    """Additional hardening surface: auth stack, logging, sensitive launch paths."""
    kernel = [
        ("fs.suid_dumpable", "SUID core dumps", {"0"}, "high"),
        ("kernel.perf_event_paranoid", "Unprivileged performance profiling", {"2", "3", "4"}, "low"),
        ("kernel.kexec_load_disabled", "Kernel kexec loading", {"1"}, "medium"),
        ("kernel.unprivileged_bpf_disabled", "Unprivileged BPF", {"1", "2"}, "medium"),
    ]
    for key, label, acceptable, severity in kernel:
        val = probe.sysctl(key)
        if val is None:
            status = "UNKNOWN"
        elif val in acceptable or (key == "kernel.perf_event_paranoid" and val.lstrip("-").isdigit() and int(val) >= 2):
            status = "PASS"
        else:
            status = "WARN"
        yield finding("kernel." + key, "Kernel", label, status, severity,
                      "Control can have workload/diagnostics compatibility implications",
                      f"{key}: {val or 'unavailable'}", "Review compatibility and distribution policy before tightening.")
    pam_paths = ("/etc/pam.d/common-password", "/etc/pam.d/password-auth", "/etc/pam.d/system-auth")
    pam_reads = []
    for path in pam_paths:
        try:
            exists = Path(path).exists()
        except OSError:
            pam_reads.append((path, None))
            continue
        if exists:
            pam_reads.append((path, probe.read(path)))
    readable = [(path, data) for path, data in pam_reads if data is not None]
    if readable:
        references = [path for path, data in readable if any(re.search(
            r"^\s*password\s+(?:\[[^]]+\]|\S+)\s+(?:\S*/)?pam_(?:pwquality|cracklib)\.so\b", line)
            for line in data.splitlines() if not line.lstrip().startswith("#"))]
        partial = len(readable) != len(pam_reads)
        yield finding("auth.pam_quality", "Authentication", "PAM password quality",
                      "UNKNOWN" if partial else "INFO" if references else "WARN", "medium",
                      "Module references are inventory; complete PAM enforcement is not established",
                      "Quality module references in: " + (", ".join(references) or "none of the readable candidate stacks")
                      + ("; some candidate files were unreadable or incomplete" if partial else ""),
                      "Review control flags, included stacks, module arguments and site policy; module presence alone is insufficient.")
    else:
        yield finding("auth.pam_quality", "Authentication", "PAM password quality", "UNKNOWN", "low",
                      "Distribution PAM layout differs or candidate files are unavailable")
    # Metadata-only SSH keys; never read contents or write private key paths into reports.
    for name, path in (("current_user", Path.home() / ".ssh"),):
        try:
            directory = path.lstat()
            insecure = (not stat.S_ISDIR(directory.st_mode) or bool(stat.S_IMODE(directory.st_mode) & 0o022)
                        or directory.st_uid not in {0, os.geteuid()})
            evidence = f"{path}: permissions {stat.S_IMODE(directory.st_mode):04o}"
            yield finding("auth.ssh_dir", "Authentication", "SSH directory permissions", "FAIL" if insecure else "PASS", "medium",
                          "Directory must not be writable by other users", evidence,
                          "Review .ssh ownership, permissions and login policy.")
            if not stat.S_ISDIR(directory.st_mode):
                continue
            for filename in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
                keyfile = path / filename
                try:
                    keymeta = keyfile.lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    yield finding("auth.key_perm." + filename, "Authentication", f"SSH private key file mode ({filename})",
                                  "UNKNOWN", "high", "Key metadata could not be inspected")
                    continue
                bad = (not stat.S_ISREG(keymeta.st_mode) or bool(stat.S_IMODE(keymeta.st_mode) & 0o077)
                       or keymeta.st_uid not in {0, os.geteuid()})
                yield finding("auth.key_perm." + filename, "Authentication", f"SSH private key file mode ({filename})",
                              "FAIL" if bad else "PASS", "high", "Metadata check only, no private key contents read",
                              f"permissions: {stat.S_IMODE(keymeta.st_mode):04o}; owner UID {keymeta.st_uid}",
                              "A private key normally must not be accessible to group or others.")
        except FileNotFoundError:
            continue
        except OSError:
            yield finding("auth.ssh_dir", "Authentication", "SSH directory permissions", "UNKNOWN", "medium",
                          "Unable to stat home SSH directory")
    for path in ("/etc/crontab", "/etc/cron.d", "/etc/systemd/system"):
        try:
            meta = os.stat(path, follow_symlinks=False)
            expected_type = stat.S_ISREG(meta.st_mode) if path == "/etc/crontab" else stat.S_ISDIR(meta.st_mode)
            bad = meta.st_uid != 0 or bool(stat.S_IMODE(meta.st_mode) & 0o022)
            yield finding("startup." + path.strip("/").replace("/", "_"), "Persistence",
                          f"Startup configuration permissions: {path}", "UNKNOWN" if not expected_type else "FAIL" if bad else "PASS", "high",
                          "System startup paths must not be writable by unprivileged users",
                          f"mode {stat.S_IMODE(meta.st_mode):04o}; owner UID {meta.st_uid}; expected file type: {expected_type}",
                          "Inspect ownership/modes for entries and nested unit files too.")
        except OSError as exc:
            yield finding("startup." + path.strip("/").replace("/", "_"), "Persistence",
                          f"Startup configuration permissions: {path}", "UNKNOWN", "high", "Startup path metadata unavailable", str(exc))
    for unit, label in (("systemd-journald.service", "System journal"),
                        ("systemd-timesyncd.service", "Time synchronization")):
        value = command_service(probe, unit)
        # Time synchronization may be provided by chrony/ntpd, not only timesyncd.
        if unit.startswith("systemd-timesyncd") and value != "active":
            alternatives = [command_service(probe, u) for u in ("chrony.service", "chronyd.service", "ntpsec.service", "ntp.service")]
            value = "active (alternate)" if "active" in alternatives else value
        yield finding("system." + unit, "Monitoring", label,
                      "PASS" if value and value.startswith("active") else "WARN" if value else "UNKNOWN", "low",
                      "Reliable logs and timestamps support incident response", f"State: {value or 'unknown'}",
                      "Verify retained logs, clock synchronization and monitoring integrations.")
    data = probe.read("/etc/systemd/journald.conf")
    storage_values = [line.split("=", 1)[1].strip() for line in (data or "").splitlines()
                      if re.match(r"^\s*Storage\s*=", line)]
    storage = storage_values[-1] if storage_values else "not specified in main file"
    yield finding("system.log_retention", "Monitoring", "Journal storage policy", "INFO" if data is not None else "UNKNOWN", "info",
                  "Main configuration only; drop-ins and journal directory availability can alter effective retention",
                  f"Main-file Storage: {storage}" if data is not None else "Main journal configuration is unavailable or incomplete",
                  "Verify effective configuration, retained logs, forwarding and rate limits.")
    if probe.which("mokutil"):
        r = probe.run("mokutil", "--sb-state")
        yield finding("firmware.secure_boot", "Platform", "UEFI Secure Boot", "INFO" if _complete(r) else "UNKNOWN", "low",
                      "Secure Boot applicability depends on firmware, boot chain and platform threat model",
                      r.out.strip() if _complete(r) else r.error[:120])
