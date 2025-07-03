# LinFo Script Changelog: v0.1 → v0.6

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### General Changes

* **Version incremented from 0.1 to 0.6**, reflecting major improvements and feature additions.
* Added a **configuration section** with flags: `SHOW_ART`, `SKIP_IP`, `RUN_SCAN`, and `RUN_LOOT`.
* **Introduced command-line argument parsing** with detailed options for `--scan`, `--loot`, `--c2ready`, `--fullscan`, and help flags.
* Added **help message output** with detailed descriptions, usage examples, and notes.
* Added a **root privilege check with interactive prompt** for automatic `sudo` rerun if not root.
* Improved **color and text styling system**, including new background color variables and text styles (`UNDERLINED`, `ITALIC`, etc.).
* Switched from simple inline color codes to more structured variables including SED-style color variables for future text processing.

---

### Functional Enhancements

#### System Info Gathering:

* Modularized system info retrieval into functions:

  * `get_os()`
  * `get_cpu()`
  * `get_gpu()`
  * `get_memory()`
  * `get_disk()`
  * `get_packages()` — added RPM support fallback
  * `get_de()`
  * `get_resolution()`
  * `get_interfaces()`
  * `get_interface_ip()`

* Improved **kernel and system info display** with architecture and shell version details.

* Added **logged-in users count** (`who | wc -l`).

* Enhanced network interface display includes MAC addresses alongside IPs.

* Added **root permission warning** for partial report accuracy.

---

### Security Scanning

* Added a **dedicated `run_scan_report()` function**:

  * Root access check.
  * Firewall active status with support for `ufw` and `iptables`.
  * SSH daemon running status.
  * SELinux/AppArmor detection.
  * Detailed kernel hardening report (`get_kernel_hardening()`):

    * SELinux enforcement
    * AppArmor status
    * Yama LSM `ptrace_scope`
    * Kernel hardening flags from `dmesg` (SMEP, SMAP, NX, stack protector)
    * Grsecurity detection
    * Stack protector config from kernel config
    * NX bit support
  * Kernel exploitability estimation (kernel version check < 5.15).
  * Count of SUID binaries in standard paths.
  * Listing suspicious SUID binaries outside standard paths.
  * `/etc/shadow` file permissions.
  * Crontab directories count.
  * Counts of world-writable directories and files.
  * Listening TCP ports via `ss`.
  * Detection of extra UID 0 users.
  * Writable NFS/Samba shares detection (using `showmount`).
  * PATH environment dangers (current directory in PATH and writable PATH entries).
  * Detection of unusual background processes (nc, python sockets, dev/tcp, etc.).
  * Unsigned kernel modules detection.
  * Suspicious environment variables related to library preloading and PATH issues.

---

### Loot Gathering

* Added `run_loot_gather()` function that collects potential system "loot" relevant for red team or C2 readiness:

  * Potential C2 staging directories (world-writable temp dirs).
  * Mounted filesystems excluding virtual ones.
  * User cron jobs with non-comment lines.
  * Writable binaries found in user PATH directories.
  * Users with last login info (`who`).
  * SSH `authorized_keys` files for all users.
  * Hidden files and directories in `/tmp` and `/var/tmp`.
  * Cron jobs with potentially suspicious commands targeting writable or temp directories.
  * Last 10 commands from users' `.bash_history` files.
  * Detailed listing of SUID binaries.
  * Suspicious shell startup files containing keywords related to common backdoors or remote execution.
  * Recently modified temp binaries (last 2 days).
  * Recently modified SUID binaries (last 7 days).

---

### Output Handling and UX

* Added **interactive output handlers for scan, loot, and fullscan** to prompt user whether to save output to a file, with filename suggestions, overwrite confirmation, or fallback to terminal output.

  * `scan_output_handler()`
  * `loot_output_handler()`
  * `fullscan_output_handler()`

* These handlers improve usability by managing potentially lengthy output gracefully.

---

### Execution Flow

* Script now **runs one or more modes depending on command line arguments**:

  * `--scan` → runs security scan report.
  * `--loot` or `--c2ready` → runs loot gathering.
  * `--fullscan` → runs both scan and loot, skipping IP info for speed.

---

### Other Notable Improvements

* Removed hard-coded system commands in favor of **checking availability with `command -v`** before running.
* Defensive coding and fallback mechanisms added, e.g., fallback for OS detection, CPU info.
* File path and permissions checks now include error handling.
* Use of `awk`, `sed`, and `grep` improved for better parsing and reliability.
* Overall script structure improved, better modularity, and readability.

---

# Summary

The update from LinFo v0.1 to v0.6 is a comprehensive overhaul adding:

* Command-line interface with options and help.
* Modular system info functions.
* Root elevation prompt.
* In-depth security scanning with kernel hardening and system checks.
* Extensive loot gathering for reconnaissance.
* Interactive output file saving.
* Better error handling, fallbacks, and usability.
* Enhanced colors and display styles.

This version turns LinFo from a simple info dump into a powerful enumeration and security reconnaissance tool suitable for red team or pentest contexts.

