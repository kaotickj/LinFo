# LinFo v0.7

|                                                              |
| ![LinFo. Unveiling the Magic of Your Linux System!](LinFo.png) |
|                                                              |

> LinFo is a lightweight Linux system information and security enumeration tool designed for quick, comprehensive insights into a target system’s hardware, software, and security posture. It is intended for use by system administrators, penetration testers, and security researchers who need an efficient way to gather system details and identify potential security weaknesses. 

---

## Features

- Collects detailed OS and kernel information.
- Reports CPU, GPU, memory, disk usage, and package count.
- Detects desktop environment and display resolution.
- Enumerates network interfaces and IP/MAC addresses.
- Provides an extensive security report covering firewall status, SELinux/AppArmor, kernel hardening features, SUID binaries, permissions, listening ports, and more.
- Gathers "loot" relevant for red team operations: suspicious cron jobs, writable directories, SSH authorized keys, shell startup files, and recently modified binaries.
- Interactive prompts for saving scan or loot reports to file.
- Supports running with or without root privileges, with full functionality recommended under root.
- Command-line options for scanning, loot gathering, hardening evaluation or all three combined.

---

## Installation

Clone or download the repository:

```bash
git clone https://github.com/kaotickj/LinFo.git
cd LinFo
chmod +x linfo.sh
````

Run the script directly on the target Linux system.

---

## Usage

```
Usage: linfo.sh [OPTIONS]

Options:

  --quiet               Run script in quiet mode (minimal output).
  --no-ip               Skip displaying network interface IP addresses.
  --raw                 Output raw, uncolored text for easier parsing.
  --scan                Perform security scanning checks and display a security report.
  --loot, --c2ready     Gather potential loot, indicators, and staging areas for C2 readiness.
  --fullscan            Run both --scan and --loot checks; skips IP info for speed.
  --help, -h            Show this help message and exit.

Examples:

  ./linfo.sh --scan
      Run only the security scan report.

  ./linfo.sh --loot
      Run loot gathering report.

  ./linfo.sh --fullscan
      Run full security and loot reports in one execution.
```

---

## ⚙️ Command-Line Switches

This script supports several operational modes that can be invoked via command-line switches. Each switch enables a distinct functionality for system enumeration, vulnerability assessment, or reporting. The following sections describe each supported switch in detail:

### `--scan`

Performs a **basic security posture scan** of the target Linux system. This includes:

* Root access check
* Firewall activity check
* SSH service status
* SELinux or AppArmor status
* Kernel hardening flag detection (SMEP, SMAP, NX, stack protector)
* SUID binary checks (standard and suspicious paths)
* `/etc/shadow` permissions
* Crontab directories
* World-writable directories and files
* Listening TCP ports
* Extra users with UID 0 (root-equivalent accounts)
* Writable NFS/Samba shares
* Dangerous or malformed `PATH` entries
* Suspicious background processes (e.g., netcat or socket-based backdoors)
* Unsigned kernel modules
* Suspicious environment variables

The results are displayed in the terminal or optionally saved to a timestamped `scan_report_YYYYMMDD_HHMMSS.txt` file.

---

### `--loot`

Executes **loot gathering mode**. This is a more offensive-focused enumeration mode, useful during Red Team operations or internal audit scenarios. It collects:

* Writable temp directories potentially usable for staging malware or C2 implants (`/tmp`, `/var/tmp`, `/dev/shm`)
* Mounted local and removable filesystems (excluding proc/sys/dev virtual mounts)
* Active crontab entries for all users
* Writable binaries in user `$PATH`
* Existence of files or paths useful for privilege escalation or data exfiltration

You will be prompted to save the output to a file (e.g., `loot_report_YYYYMMDD_HHMMSS.txt`), or view the information in the terminal.

---

### `--hardening-check`

Conducts a **system hardening assessment**. This includes:

* Detection of package manager (APT, DNF, YUM, Zypper, Pacman)
* Number of pending package updates
* Status and presence of hardening tools:

  * `fail2ban`
  * `auditd`
  * `aide`
  * `firewalld` / `ufw`
  * AppArmor or SELinux
* SSH root login permission check (`PermitRootLogin`)
* PAM password complexity enforcement (`pam_pwquality` or `pam_cracklib`)
* Intrusion detection presence (`aide`, `ossec`)
* Audit logging functionality (`auditd`)
* Presence of automatic security update mechanisms (`unattended-upgrades`, `dnf-automatic`)

The output helps assess whether the system meets modern hardening baselines. Results can be saved to a `hardening_report_YYYYMMDD_HHMMSS.txt` file.

---

### `--fullscan`

Executes both the **scan** and **loot** functions in a single operation. This is the most comprehensive mode and is useful for full assessments or reporting during incident response or red team recon.

* Executes `--scan`
* Then runs `--loot`

You will be prompted whether to save the combined output to a timestamped file (e.g., `fullscan_report_YYYYMMDD_HHMMSS.txt`).

---

### Additional Behavior and Flags

* If **run without switches**, the script performs basic host information gathering:

  * OS, hostname, uptime, package count
  * Desktop environment (if applicable)
  * Screen resolution, terminal, shell
  * CPU, GPU, memory, disk usage
  * Logged-in users and network interfaces with IP/MAC addresses

* Root privileges are **recommended** for complete scan accuracy, especially to access:

  * Full firewall configurations
  * SUID binaries outside standard paths
  * Environment variable security checks
  * Access-controlled cron jobs and audit logs

* If the variable `SKIP_IP=1` is set manually, the script **skips displaying network interface IP addresses**, useful in airgapped/offline assessments or anonymized outputs.

* If `SHOW_ART=1`, an ASCII header banner and attribution will be shown.

---

### 🔐 Permissions Warning

If the script detects it is **not run as root**, it will display a warning, as some features may return incomplete or misleading results without elevated privileges.

---

### Example Usage

```bash
./LinFo.sh --scan
./LinFo.sh --loot
./LinFo.sh --hardening-check
./FinFo.sh --fullscan
```

Each mode will prompt you to save the output or display it directly, based on your interaction.

---

## License

This project is licensed under the GPL-3 License. See the [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open issues or pull requests on GitHub.

---

## Disclaimer

Use this tool responsibly and only on systems where you have explicit permission to perform security assessments.