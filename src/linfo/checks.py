"""Read-only local security controls. A missing tool or denied access is UNKNOWN, not PASS."""
from __future__ import annotations
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
from typing import Callable, Iterator
from .models import Finding
from .probe import Probe
from .management import detect_platform

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
    return Finding(id, category, title, status, severity, summary, evidence[:1600],
                   recommendation, action_id, reference)


def command_service(probe: Probe, unit: str) -> str | None:
    if not probe.which("systemctl"):
        return None
    r = probe.run("systemctl", "is-active", unit)
    if r.out.strip() in {"active", "inactive", "failed", "activating", "deactivating", "unknown"}:
        return r.out.strip()
    return None


def sysctl_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    controls = [
        ("aslr", "Kernel ASLR", "kernel.randomize_va_space", "2", "high", "aslr"),
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
        passed = (got == wanted or (ident == "ptrace" and got in {"2", "3"}))
        yield finding("sysctl." + ident, "Kernel", title, "PASS" if passed else "WARN", severity,
                      "Effective runtime kernel setting", f"{key} = {got}; desired: {wanted}",
                      "Review workload compatibility before changing kernel sysctls.",
                      None if passed else action,
                      "https://man7.org/linux/man-pages/man5/sysctl.d.5.html")


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
            mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
            bad = bool(mode & 0o003) if path == "/etc/passwd" else bool(mode & 0o007)
            # /etc/passwd is expected to be world-readable, but never world-writable.
            if path == "/etc/passwd":
                bad = bool(mode & 0o022)
            yield finding("file." + Path(path).name, "Permissions", label,
                          "FAIL" if bad else "PASS", "high", "Check sensitive account file permissions",
                          f"{path}: {mode:04o}", "Review owner/mode against your distribution's policy. Never apply generic chmod blindly.")
        except OSError as exc:
            yield finding("file." + Path(path).name, "Permissions", label, "UNKNOWN", "medium",
                          "File not accessible", str(exc))
    for path in ("/tmp", "/var/tmp", "/dev/shm"):
        try:
            mode = os.stat(path).st_mode
            if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
                status = "FAIL"
            else:
                status = "PASS"
            yield finding("file.temp." + path.strip("/").replace("/", "_"), "Permissions",
                          f"Sticky bit on {path}", status, "high", "World-writable shared directories need sticky-bit protection",
                          f"{path}: {stat.S_IMODE(mode):04o}", "Set the sticky bit after checking intended directory use.")
        except OSError:
            pass


def ssh_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)
    if not sshd:
        yield finding("ssh.available", "SSH", "SSH server", "INFO", "info", "sshd binary not found; no SSH server configuration evaluated")
        return
    active = command_service(probe, "ssh.service") == "active" or command_service(probe, "sshd.service") == "active"
    yield finding("ssh.service", "SSH", "SSH service", "INFO", "info", "Service state is inventory, not a vulnerability",
                  "active" if active else "not confirmed active")
    r = probe.run(sshd, "-T", timeout=10)
    if not r.ok:
        yield finding("ssh.config", "SSH", "Effective SSH configuration", "UNKNOWN", "medium",
                      "Cannot obtain effective global sshd configuration; may require root",
                      (r.error or r.out)[:900], "Use 'sudo sshd -T' and validate relevant Match contexts.")
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
            mode = sshconf.stat().st_mode
            bad = bool(mode & 0o022)
            yield finding("ssh.config_perm", "SSH", "SSH configuration writability", "FAIL" if bad else "PASS", "high",
                          "Unprivileged writes to SSH configuration must be prohibited",
                          f"{sshconf}: {stat.S_IMODE(mode):04o}")
        except OSError:
            pass


def firewall_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    ufw = probe.run("ufw", "status") if probe.which("ufw") else None
    if ufw and ufw.ok and re.search(r"^Status:\s+active\b", ufw.out, re.M | re.I):
        yield finding("network.firewall", "Network", "Host firewall", "PASS", "high",
                      "UFW reports active", "ufw status: active", "Verify allow rules and policy for required services.")
        return
    if probe.which("firewall-cmd"):
        fw = probe.run("firewall-cmd", "--state")
        if fw.ok and fw.out.strip() == "running":
            yield finding("network.firewall", "Network", "Host firewall", "PASS", "high",
                          "firewalld reports running", "firewall-cmd --state: running",
                          "Review active zones and filtering rules.")
            return
    if probe.which("nft"):
        r = probe.run("nft", "-j", "list", "ruleset")
        if r.ok:
            try:
                rules = json.loads(r.out).get("nftables", [])
                relevant = [x for x in rules if "chain" in x or "rule" in x]
                # Presence of rules alone does not prove enforcement.
                yield finding("network.firewall", "Network", "Host firewall", "WARN" if relevant else "FAIL", "high",
                              "nftables rules detected but policy must be reviewed" if relevant else "Empty nftables ruleset",
                              f"{len(relevant)} chain/rule objects", "Review input/output/forward base-chain policies and actual exposure.")
            except (ValueError, TypeError):
                yield finding("network.firewall", "Network", "Host firewall", "UNKNOWN", "high",
                              "nft output could not be interpreted")
            return
        yield finding("network.firewall", "Network", "Host firewall", "UNKNOWN", "high",
                      "Firewall rules could not be inspected without additional privileges", r.error or r.out[:300])
        return
    if ufw and not ufw.ok:
        yield finding("network.firewall", "Network", "Host firewall", "UNKNOWN", "high", "UFW could not be queried", ufw.error)
    else:
        yield finding("network.firewall", "Network", "Host firewall", "UNKNOWN", "high",
                      "No supported runtime firewall backend available to assess", "Not equivalent to no firewall")


def network_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    r = probe.run("ss", "-H", "-lntu")
    if not r.ok:
        yield finding("network.listeners", "Network", "Listening network sockets", "UNKNOWN", "medium",
                      "ss not available", r.error)
        return
    lines = r.out.splitlines()
    yield finding("network.listeners", "Network", "Listening TCP/UDP endpoints", "INFO", "info",
                  "Inventory; include listeners not just TCP LISTEN", "\n".join(lines[:18]) + (f"\n... ({len(lines)} total)" if len(lines)>18 else ""))
    flagged = []
    sensitive_ports = {21, 23, 111, 139, 445, 3306, 5432, 5900, 6379, 9200, 11211, 27017}
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            continue
        addr = fields[4]
        try:
            port = int(addr.rsplit(":", 1)[-1])
        except ValueError:
            continue
        if port in sensitive_ports and (addr.startswith("0.0.0.0:") or addr.startswith("[::]:") or addr.startswith("*:") or addr.startswith(":::") ):
            flagged.append(addr)
    yield finding("network.exposed", "Network", "Sensitive services listening on all interfaces",
                  "WARN" if flagged else "PASS", "high", "Potentially exposed high-impact service ports; confirm network boundaries",
                  ", ".join(flagged[:25]) or "None of the selected ports exposed on wildcard addresses",
                  "Bind services to trusted addresses and verify firewall rules where appropriate.")


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
    distro = Probe.read("/etc/os-release") or ""
    if probe.which("apt") and ("ID=debian" in distro or "ID=ubuntu" in distro or "ID_LIKE=debian" in distro or "ID_LIKE=ubuntu" in distro):
        r = probe.run("apt", "list", "--upgradable", timeout=15)
        if r.ok:
            lines = [s for s in r.out.splitlines() if "/" in s and "upgradable" in s]
            yield finding("package.pending", "Packages", "Cached package upgrades", "WARN" if lines else "PASS", "medium",
                          "Cached APT metadata only; a fresh repository refresh may change results",
                          f"{len(lines)} upgradable packages in current cache",
                          "Review and install applicable security updates after testing; refresh package metadata.")
        else:
            yield finding("package.pending", "Packages", "Cached package upgrades", "UNKNOWN", "medium",
                          "Unable to check cached APT upgrades", r.error or r.out[:250])
        installed = probe.run("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
        files = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        config = Probe.read(str(files)) or ""
        enabled = bool(re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', config))
        yield finding("package.automatic", "Packages", "Automatic security upgrades",
                      "PASS" if installed.ok and "install ok installed" in installed.out and enabled else "WARN", "medium",
                      "Package installed and periodic configuration are separate checks",
                      f"unattended-upgrades installed: {installed.ok and 'install ok installed' in installed.out}; periodic enabled: {enabled}",
                      "Review unattended-upgrades sources, schedules and reboot policy.")
    else:
        platform = detect_platform()
        manager = platform.package_manager
        candidates = {
            'dnf': ('dnf', 'check-update', '--quiet'),
            'yum': ('yum', 'check-update', '--quiet'),
            'zypper': ('zypper', '--non-interactive', 'list-updates'),
            'pacman': ('pacman', '-Qu'),
        }
        if manager not in candidates:
            yield finding('package.pending', 'Packages', 'Cached package updates', 'UNKNOWN', 'medium',
                          'No supported package manager detected', 'Not equivalent to zero updates')
        else:
            r = probe.run(*candidates[manager], timeout=18)
            # dnf/yum exit code 100 means updates available, not a command failure.
            if manager in {'dnf', 'yum'} and r.returncode in (0, 100):
                status = 'WARN' if r.returncode == 100 else 'PASS'
                summary = 'Cached metadata indicates updates' if status == 'WARN' else 'No cached updates detected'
            elif manager == 'pacman' and r.returncode in (0, 1):
                status = 'WARN' if r.out.strip() else 'PASS'
                summary = 'Local sync DB contains pending package upgrades' if status == 'WARN' else 'No cached updates detected'
            elif manager == 'zypper' and r.ok:
                body = [row for row in r.out.splitlines() if ' | ' in row and not row.lstrip().startswith(('S |', '--'))]
                status = 'WARN' if body else 'PASS'
                summary = 'Cached zypper metadata indicates updates' if body else 'No cached updates detected'
            else:
                status, summary = 'UNKNOWN', 'Package manager update query failed'
            yield finding('package.pending', 'Packages', 'Cached package updates', status, 'medium',
                          summary, (r.out or r.error)[:300],
                          'Refresh metadata and validate updates using the distro-native package manager.')


def integrity_findings(probe: Probe, profile: str) -> Iterator[Finding]:
    for key, label in (("/proc/sys/kernel/kptr_restrict", "Kernel pointer exposure"),
                       ("/proc/sys/kernel/dmesg_restrict", "Kernel log access")):
        data = Probe.read(key, 80)
        if data is None:
            status = "UNKNOWN"
        else:
            status = "PASS" if data.strip() not in ("0", "") else "WARN"
        yield finding("kernel." + key.rsplit("/", 1)[-1], "Kernel", label, status, "low",
                      "Kernel diagnostic visibility may be intentionally enabled for troubleshooting",
                      f"{key} = {data.strip() if data is not None else 'unknown'}")
    # LSM may be active even if aa-status/getenforce is not available.
    lsm = Probe.read("/sys/kernel/security/lsm", 500)
    aa = Probe.read("/sys/module/apparmor/parameters/enabled", 50)
    sel = Probe.read("/sys/fs/selinux/enforce", 20)
    enabled = (aa is not None and aa.strip().upper().startswith("Y")) or (sel is not None and sel.strip() == "1")
    yield finding("kernel.lsm", "Kernel", "Mandatory access control", "PASS" if enabled else "WARN" if lsm else "UNKNOWN", "medium",
                  "Kernel LSM registered does not necessarily mean policies enforce confinement",
                  f"LSM: {(lsm or 'unavailable').strip()}; AppArmor: {(aa or 'unknown').strip()}; SELinux enforce: {(sel or 'unknown').strip()}",
                  "Inspect the chosen LSM and application confinement policy, not just module presence.")
    for path in ("/tmp", "/var/tmp"):
        r = probe.run("findmnt", "-n", "-o", "OPTIONS", "-T", path) if probe.which("findmnt") else None
        if r and r.ok:
            opts = set(r.out.strip().split(","))
            yield finding("mount." + path.strip("/"), "Filesystems", f"Filesystem options for {path}", "INFO", "low",
                          "Mount options depend on workload and partition layout",
                          ", ".join(sorted(opts)), "Consider noexec/nosuid/nodev only after compatibility review.")
    # Report count only, do not dump every path or collect sensitive contents.
    paths = [p for p in ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin") if Path(p).is_dir()]
    if paths and probe.which("find"):
        r = probe.run("find", *paths, "-xdev", "-type", "f", "-perm", "/4000", "-print", timeout=18)
        if r.ok:
            entries = [p for p in r.out.splitlines() if p]
            yield finding("file.suid", "Permissions", "SUID executable inventory", "INFO", "medium",
                          "SUID is not by itself a vulnerability. Compare a saved baseline and investigate unexpected changes.",
                          f"{len(entries)} SUID files in standard binary directories")
        else:
            yield finding("file.suid", "Permissions", "SUID executable inventory", "UNKNOWN", "medium",
                          "Incomplete scan", r.error)
    else:
        yield finding("file.suid", "Permissions", "SUID executable inventory", "UNKNOWN", "medium", "find unavailable")
    for path in ("/etc", "/usr/local/bin", "/usr/local/sbin"):
        if not Path(path).is_dir() or not probe.which("find"):
            continue
        r = probe.run("find", path, "-xdev", "-type", "f", "-perm", "/0002", "-print", timeout=12)
        if r.ok:
            files = r.out.splitlines()
            yield finding("file.worldwrite." + path.strip("/").replace("/", "_"), "Permissions",
                          f"World-writable files in {path}", "FAIL" if files else "PASS", "high",
                          "Regular files with other-write bit set", f"{len(files)} file(s): " + ", ".join(files[:5]),
                          "Review ownership and purpose before tightening permissions.")
        else:
            yield finding("file.worldwrite." + path.strip("/").replace("/", "_"), "Permissions",
                          f"World-writable files in {path}", "UNKNOWN", "medium", "Scan incomplete", r.error)


def hardening_checks(probe: Probe, profile: str, progress: Callable[[str], None] | None = None) -> list[Finding]:
    categories = [sysctl_findings, account_findings, ssh_findings, firewall_findings,
                  network_findings, access_findings, package_findings, integrity_findings, extra_findings]
    out: list[Finding] = []
    for group in categories:
        if progress:
            progress(f"Running {group.__name__.replace('_findings', '')} checks…")
        try:
            out.extend(group(probe, profile))
        except Exception as exc:
            # Partial results remain useful, unexpected probe failures must not be counted as PASS.
            out.append(finding("error." + group.__name__, "Scanner", "Scanner module error", "UNKNOWN", "medium",
                               "Module failed; checks in this category may be incomplete", f"{type(exc).__name__}: {exc}"))
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
    auth = Path("/etc/pam.d/common-password")
    if auth.exists():
        data = probe.read(str(auth))
        if data is not None:
            active = [line.strip() for line in data.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            uses_quality = any("pam_pwquality.so" in s or "pam_cracklib.so" in s for s in active)
            yield finding("auth.pam_quality", "Authentication", "PAM password quality", "PASS" if uses_quality else "WARN", "medium",
                          "Presence of a quality module does not verify complete settings",
                          "pwquality/cracklib module configured" if uses_quality else "No pwquality/cracklib module in common-password",
                          "Evaluate site password policy and PAM stack; passwordless authentication can have different requirements.")
    else:
        yield finding("auth.pam_quality", "Authentication", "PAM password quality", "UNKNOWN", "low",
                      "Distribution PAM layout differs or is unavailable")
    # Metadata-only SSH keys; never read contents or write private key paths into reports.
    for name, path in (("current_user", Path.home() / ".ssh"),):
        if not path.exists():
            continue
        try:
            directory = path.lstat()
            insecure = not stat.S_ISDIR(directory.st_mode) or bool(stat.S_IMODE(directory.st_mode) & 0o022)
            evidence = f"{path}: permissions {stat.S_IMODE(directory.st_mode):04o}"
            yield finding("auth.ssh_dir", "Authentication", "SSH directory permissions", "FAIL" if insecure else "PASS", "medium",
                          "Directory must not be writable by other users", evidence,
                          "Review .ssh ownership, permissions and login policy.")
            for filename in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
                keyfile = path / filename
                if not keyfile.exists():
                    continue
                keymeta = keyfile.lstat()
                bad = not stat.S_ISREG(keymeta.st_mode) or bool(stat.S_IMODE(keymeta.st_mode) & 0o077)
                yield finding("auth.key_perm." + filename, "Authentication", f"SSH private key file mode ({filename})",
                              "FAIL" if bad else "PASS", "high", "Metadata check only, no private key contents read",
                              f"permissions: {stat.S_IMODE(keymeta.st_mode):04o}",
                              "A private key normally must not be accessible to group or others.")
        except OSError:
            yield finding("auth.ssh_dir", "Authentication", "SSH directory permissions", "UNKNOWN", "medium",
                          "Unable to stat home SSH directory")
    for path in ("/etc/crontab", "/etc/cron.d", "/etc/systemd/system"):
        try:
            meta = os.stat(path, follow_symlinks=False)
            bad = bool(stat.S_IMODE(meta.st_mode) & 0o022)
            yield finding("startup." + path.strip("/").replace("/", "_"), "Persistence",
                          f"Startup configuration permissions: {path}", "FAIL" if bad else "PASS", "high",
                          "System startup paths must not be writable by unprivileged users",
                          f"mode {stat.S_IMODE(meta.st_mode):04o}",
                          "Inspect ownership/modes for entries and nested unit files too.")
        except OSError:
            pass
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
    data = Probe.read("/etc/systemd/journald.conf") or ""
    storage = next((line.split("=", 1)[1].strip() for line in data.splitlines()
                    if line.strip().startswith("Storage=")), "auto/default")
    yield finding("system.log_retention", "Monitoring", "Journal storage policy", "INFO", "info",
                  "Storage=auto depends on journal directory availability; service status alone does not confirm retention",
                  f"Configured storage: {storage}", "Verify retention, forwarding, rate limits and central logging requirements.")
    if probe.which("mokutil"):
        r = probe.run("mokutil", "--sb-state")
        yield finding("firmware.secure_boot", "Platform", "UEFI Secure Boot", "INFO", "low",
                      "Secure Boot applicability depends on firmware, boot chain and platform threat model",
                      r.out.strip() if r.ok else (r.error or r.out)[:120])
