# LinFo 0.7 Alpha

**Original LinFo project by Kaotick Jay**  
Linux system inventory, local security assessment, and guided hardening using Python and PyQt6.

Version **0.7.0a2** continues the existing Python application and its management tools. Assessments run in the background, show findings as checks finish, and can be cancelled while retaining a partial report. This remains a development alpha, not an audited or compliance-certifying security suite.

## Install on Debian 13

For a built Debian package, open a terminal in its download directory:

```bash
sha256sum -c linfo_0.7.0~a2_all.deb.sha256
sudo apt install ./linfo_0.7.0~a2_all.deb
linfo
```

The package adds an application-menu entry and depends on distribution Python 3.10+ and **python3-pyqt6 6.5+**. Debian 13 is the target; older distributions may not provide the required Qt binding version. The package includes the optional privileged helper's source and installer, but does **not** activate the helper.

## Run from the development branch

```bash
sudo apt install git python3 python3-venv python3-pip
git clone --branch development https://github.com/kaotickj/LinFo.git
cd LinFo
python3 -m venv .venv
.venv/bin/python -m pip install -e .
./launch.sh
```

On Debian 13, an alternative is to install `python3-pyqt6` through APT and use `./launch.sh` directly. The launcher checks the project virtual environment and system Python. Run the desktop as your **normal user**, including when you intend to use guided administration. An assessment does not require the privileged helper; inaccessible checks are labeled `UNKNOWN`.

If Qt reports an `xcb` platform-plugin dependency error, check your distribution's desktop runtime libraries; Debian/Ubuntu packages used by CI include `libegl1`, `libgl1`, `libxkbcommon-x11-0`, and `libxcb-cursor0`. The `offscreen` Qt backend is for automated tests, not the interactive desktop.

## Desktop workflow

Choose the **workstation** or **server** profile and select **Run Security Assessment**. Findings appear while the assessment runs. **Cancel** stops collection and preserves completed findings for review and export. The default total assessment budget is 180 seconds; a deadline also produces a partial report.

| Tab | Available controls |
| --- | --- |
| **Overview** | Host information, assessment state, and PASS / WARN / FAIL / UNKNOWN counts. |
| **Findings** | Text search, status/category filters, sortable columns, detailed evidence, copy-finding control, and the existing **Manage** or **Review** actions. |
| **Hardening** | Review selected sysctl changes, use rollback receipts, and open allowlisted configuration files in a chosen graphical editor. |
| **Inventory** | OS, CPU, memory, kernel, mounted devices, interfaces, routes, and virtualization information where available. |
| **Activity** | Live assessment progress and management activity. |
| **Reports** | Export HTML, JSON, CSV, or plain text; open saved JSON reports; compare against a saved JSON baseline. |

The window geometry, findings-pane layout, profile, status filter, and chosen editor are remembered. Export includes the entire collected assessment, regardless of the current table filter. CSV contains finding rows; retain JSON, HTML, or TXT when you also need host information and assessment-completeness metadata.

Saved JSON imports and cancelled assessments are **review-only**: they do not authorize changes to the current machine. Run a fresh local assessment before using their findings to manage this host. Missing controls in a partial comparison are marked **not observed**, rather than treated as fixed or removed.

## Headless and automation usage

```bash
.venv/bin/linfo --cli --profile server --timeout 180 --output server-audit.json
.venv/bin/linfo --cli --profile workstation --output workstation-audit.html
.venv/bin/linfo --cli --compare earlier-audit.json --output latest-audit.json
.venv/bin/linfo --cli --quiet --output assessment.txt
```

After installing the Debian package, use `linfo` in place of `.venv/bin/linfo`. `--headless` is an alias for `--cli`; `--output` accepts `.json`, `.html`, `.csv`, and `.txt`. Without an output file, JSON goes to stdout. Progress and comparison information go to stderr; `--quiet` suppresses progress. `--timeout` accepts 1–7200 seconds and defaults to 180.

| Exit code | Meaning |
| --- | --- |
| **0** | Assessment finished without a high/critical `FAIL`; inspect `UNKNOWN` findings and completeness metadata separately. |
| **2** | At least one high/critical `FAIL`, or a command-line argument/usage error. |
| **1** | A runtime, input, or export error prevented the requested operation. |
| **130** | Assessment cancelled by SIGINT/SIGTERM or its total deadline; a partial report is written when possible. |

Cancellation does not count as a successful assessment. Warnings and unavailable controls do not by themselves trigger exit 2.

## What gets assessed

- Account inventory, additional UID-0 accounts, administrative groups, account-database file modes, and current-user SSH key permissions using metadata only.
- TCP and UDP listeners, selected sensitive wildcard-bound ports, recognized firewall runtime state, accessible nftables policies, and IPv4 kernel network settings.
- Process ASLR, Yama ptrace restrictions, protected links, diagnostic disclosure controls, restricted BPF, kexec, core dumps, and observable MAC/LSM enforcement.
- Effective global `sshd -T` settings where accessible, with explicit limits for connection-specific `Match` blocks and a running daemon's loaded configuration.
- Cached package-update candidates for **APT, DNF/YUM, Zypper, and pacman**; effective APT unattended-upgrade configuration and its standard timer.
- Audit/monitoring services, time synchronization, system logging, AIDE presence, PAM quality-module references, SUID metadata, selected world-writable files, shared-temp sticky bits, startup-path modes, and selected mount options.

Missing tools, denied access, truncated output, unsupported formats, and failed probes produce `UNKNOWN` or explicit coverage limits. Module presence is not proof of policy enforcement; an installed firewall command is not proof of filtering. No check determines kernel exploitability from a version number alone.

### Cached update semantics

Update checks do not refresh repositories or download packages. DNF/YUM use cache-only queries with plugins disabled; Zypper uses `--no-refresh` and XML output; pacman reads its local sync databases. Plugin-provided repositories may be absent from the DNF/YUM view. DNF/YUM exit 100 means updates are available, while pacman's exit 1 is treated as an empty query only when both output and diagnostics are empty.

Zero candidates are reported as `INFO`, **not** as proof that the system is current. Cache freshness, repository completeness, and security-advisory coverage still require normal maintenance review. Non-APT adapters have parser/error regression tests; validation on each target distribution remains necessary.

Reference semantics: [APT](https://manpages.debian.org/trixie/apt/apt.8.en.html), [DNF4](https://dnf.readthedocs.io/en/latest/command_ref.html), [DNF5](https://dnf5.readthedocs.io/en/latest/dnf5.8.html), [Zypper](https://manpages.opensuse.org/Tumbleweed/zypper/zypper.8.en.html), and [pacman](https://man.archlinux.org/man/pacman.8.en.html).

## Optional guided administration

The existing management workflow is retained. **Manage** offers supported package installation, allowlisted service enable/disable operations, configuration editing through `sudoedit`, and reversible sysctl changes. Unsupported or high-impact findings remain guided manual review. Assessments themselves do not apply these changes.

After reviewing `privileged/linfo-helper`, install the root-owned helper from the source checkout:

```bash
sudo ./scripts/install-helper.sh
```

For the Debian package, inspect `/usr/share/linfo/privileged/linfo-helper`, then use:

```bash
sudo /usr/share/linfo/scripts/install-helper.sh
```

The trusted helper is installed at `/usr/local/libexec/linfo-helper`. A working PolicyKit agent and `pkexec` are required for helper operations. The GUI verifies root ownership and non-writability by other users; it never elevates the whole desktop application. Configuration editing uses a desktop terminal and the selected unprivileged graphical editor through `sudoedit`. No passwordless authorization policy is installed.

Sysctl changes are explicitly selected and cover ASLR, protected links, Yama ptrace, IPv4 redirects, and source routing. They can affect debugging, routing, or specialized security tooling. A successful sysctl transaction returns a UUID receipt and stores prior state root-only under `/var/lib/linfo/changes`. **Rollback by Receipt ID** refuses to overwrite later administrator changes or newer LinFo transactions. Preserve the receipt; interrupted changes may require manual recovery.

Package installation and service operations do **not** have transactional sysctl-style rollback. Package removal is not automated; service reversal requires reviewing dependencies. SSH/firewall configuration and package upgrades remain review-led operations, not automatic scan responses. Wait for an approved operation's result before closing the window.

Persistent sysctls are written to `/etc/sysctl.d/99-zz-linfo-hardening.conf`; other configuration or boot behavior can supersede them. Validate the effective settings after reboot.

## Reports and privacy

Assessments are host-local, with no telemetry, uploads, cloud calls, or remote network probing. LinFo does not collect credentials, SSH private-key contents, password hashes, or shell histories. Reports can still contain hostnames, addresses, usernames, and system topology.

Report exports are written atomically with owner-only **0600** permissions. HTML escapes collected text, CSV neutralizes spreadsheet-formula prefixes, and JSON imports validate bounded report data. Saved reports are evidence for review, not executable input or authorization for administration.

## Tests and builds

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q src privileged/linfo-helper
python3 scripts/build-deb.py
```

The Debian build requires `dpkg-deb` and creates `dist/linfo_0.7.0~a2_all.deb` plus its SHA-256 file. It does not install the package or activate the helper. Version metadata is derived from `src/linfo/__init__.py`.

The existing Linux build workflow produces the PyInstaller executable in the **LinFo-Linux-x86_64** artifact, and a dependency-based installer in **LinFo-Debian**. The executable bundles Python/PyQt6 but still needs compatible Linux desktop libraries. Both formats retain the optional helper as a separate, explicit installation step. CI exercises Python 3.10/3.12/3.13, offscreen GUI behavior, package parsers, reports, cancellation, and the existing helper/management tests.

## Further development

Remaining work includes a privileged read-only helper for deeper firewall/SSH assessment, validation across supported distributions, context-aware hardening plans with preflight/recovery, versioned benchmark policies and exceptions, and independent review of privileged operations. LinFo does not claim CIS, DISA STIG, NIST, or PCI certification.

## Licensing

See the repository's existing [GNU General Public License v3](LICENSE). Original concept and authorship: **Kaotick Jay**.
