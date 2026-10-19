# LinFo 0.6 Alpha

**Original LinFo project by Kaotick Jay**  
Linux security inventory, hardening assessment, and controlled remediation using Python and PyQt6.

This is a functional **first development milestone**, not an audited, compliant or production-certifying security suite. It intentionally does not execute exploitation, collect credentials, read shell histories, or automatically reconfigure SSH/firewalls.

## Quick start on Debian / Ubuntu (GUI)

```bash
sudo apt install python3 python3-venv python3-pip
cd LinFo
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/linfo
```

You may need PyQt6 system/Qt display libraries installed for your desktop (XFCE, KDE, Wayland or X11). Keep the GUI **unprivileged**.

## Headless / automation usage

```bash
.venv/bin/linfo --cli --profile server --output server-audit.json
.venv/bin/linfo --cli --profile workstation --output workstation-audit.html
.venv/bin/linfo --cli --profile server --compare earlier-audit.json --output latest-audit.json
```

The CLI emits progress to stderr. JSON is printed to stdout if `--output` is absent. The CLI returns code **2** if at least one high/critical `FAIL` is found. Warnings, and unavailable checks marked `UNKNOWN`, do not cause exit 2. Use strict external policies if a different CI threshold is desired.

## GUI tabs

- **Overview:** host and counts by PASS / WARN / FAIL / UNKNOWN.
- **Findings:** filterable table with severity, observed evidence, recommendations and limited links.
- **Hardening:** select narrow, reversible sysctl changes. Explicit approval + PolicyKit authorization required.
- **Inventory:** kernel, OS, RAM, CPU, mounted devices, interfaces, virtualized status where tools exist.
- **Reports:** HTML/JSON/CSV exports and a comparison against a saved JSON scan.

## Privileged remediation (optional)

Only after reviewing the `privileged/linfo-helper` source, install the **root-owned** helper:

```bash
sudo ./scripts/install-helper.sh
```

`pkexec` and a working PolicyKit authentication agent are required for GUI-based changes. No custom policy or passwordless elevation is installed. The helper must exist at `/usr/local/libexec/linfo-helper`, be root-owned and not writable by others. Do **not** run the desktop GUI using `sudo` or `pkexec`.

The helper supports only these predefined changes: ASLR, protected links, Yama ptrace restrictions, IPv4 redirect settings, and IPv4 source routing. Some are incompatible with specialized tooling, debugging, routing or security testing setups. **Nothing is selected automatically.**

On success a UUID receipt is returned and the prior state is saved root-only under `/var/lib/linfo/changes`. Enter that receipt in the GUI rollback dialog to attempt a rollback. Rollback deliberately refuses to overwrite newer administrator changes or later LinFo transactions. A crash or permission error may require manual recovery using the receipt and `/etc/sysctl.d/99-zz-linfo-hardening.conf`.

**Important:** Changes made to `/etc/sysctl.d/` are intended to persist across reboots, but may be superseded by other settings or system initialization behavior. Validate actual state on reboot. SSH/iptables/nftables/firewalld/UFW service changes and upgrades are *review-only* in this version; a bad automatic change could lock administrators out of remote hosts.

## What gets assessed

- Account inventory, additional UID-0 accounts, administrative groups, password database file permissions, current user's SSH private-key permissions (metadata only).
- Listening network services and risky wildcard-bound ports, recognized host firewall activity or accessible nftables rules, IPv4 kernel network settings.
- Kernel ASLR, Yama ptrace, protected links, memory disclosure restrictions, restricted BPF, kexec, core dumps, and available MAC/LSM status.
- Effective global SSH configuration via `sshd -T` where accessible, with an explicit caution that Match contexts can differ.
- APT cached upgrade status and unattended-upgrades configuration, selected audit and monitoring services, time sync, system logging, AIDE presence.
- SUID metadata inventory, selected world-writable files, shared temp-directory sticky bits, core startup-file modes, selected filesystem mount options.

An unavailable probe, permission denial or unsupported package manager is reported as **UNKNOWN**, not as a false PASS. In particular, an empty APT update cache does **not** prove that a system is current. No check determines exploitability merely from a Linux kernel version. Firewall command installation does not prove that traffic is filtered. Missing AIDE/Fail2ban does not automatically mean compromised.

## Security and privacy boundaries

- Host-local checks, no uploads, telemetry, cloud API calls or network probes.
- No capture of SSH private keys, password hashes, tokens or shell-history content.
- Some reports still contain hostnames, network addresses, usernames and system topology: protect report files.
- Scanner subprocesses use argument arrays and timeouts; no shell interpolation.
- Auto-remediation only uses an explicit action allowlist, root-owned executable, isolated Python interpreter, root-only backups and post-apply runtime validation.
- GUI and CLI scans are unprivileged by default; unavailable root-only checks are labeled UNKNOWN.
- No claims of CIS, DISA STIG, NIST or PCI compliance. Mapping to a particular benchmark requires a separately validated, versioned policy pack.

## Test from source

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src
```

## Planned next modules

1. Distro-specific policy adapters for Debian 13/Ubuntu, Fedora/RHEL, openSUSE and Arch (today's strong package update adapter is APT only).
2. Privileged **read-only** scan helper for firewall policies and per-context SSH effective configuration; no global elevation of the GUI.
3. Context-aware hardening plans for OpenSSH, PAM, sudo, auditd, logging, file integrity and service sandboxing, with dry-run diff, preflight checks, confirmation and recovery plans.
4. Signed, versioned benchmark/policy profiles, exceptions with expiration, drift monitoring and authenticated fleet export.
5. Application packaging, reproducible builds, CI test matrix and independent code review of privileged helper.

## Licensing

LinFo is distributed under the GNU General Public License v3, consistent with the repository's existing `LICENSE` file. The original Bash implementation remains available as [`LinFo.sh`](LinFo.sh). This development branch contains the Python GUI migration.
