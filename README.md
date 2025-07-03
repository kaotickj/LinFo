# LinFo v0.5
|       |
| ----- |
| ![LinFo. Unveiling the Magic of Your Linux System!](LinFo.png) |
|       |
LinFo is a lightweight Linux system information and security enumeration tool designed for quick, comprehensive insights into a target system’s hardware, software, and security posture. It is intended for use by system administrators, penetration testers, and security researchers who need an efficient way to gather system details and identify potential security weaknesses.

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
- Command-line options for scanning, loot gathering, or both combined.

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

## Notes

* Running with root privileges (e.g., via `sudo`) is recommended to ensure full scan accuracy and access to all system information.
* The loot report can be very detailed; the script will prompt to save output to a file if desired.
* The script attempts to detect various kernel hardening features and potential security risks, but some checks depend on kernel version and system configuration.
* Designed for Linux environments only.

---

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open issues or pull requests on GitHub.

---

## Disclaimer

Use this tool responsibly and only on systems where you have explicit permission to perform security assessments.


