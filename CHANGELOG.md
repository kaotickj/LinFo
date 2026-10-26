# Changelog

## 0.7.0a2 (2026-10-25)

- Continued the existing Python/PyQt6 application, preserving per-finding management, package/service allowlists, configuration editing, sysctl approvals, and rollback receipts.
- Added live findings, searchable/sortable tables, category/status filtering, Activity, remembered desktop settings, and cancellation that retains a clearly marked partial assessment.
- Bounded subprocess output and text reads, terminated timed-out/cancelled probe process groups, and made denied or incomplete evidence explicit.
- Added plain-text reports and validated JSON reopening for review; imported and cancelled reports cannot drive local management. Exports use atomic replacement and mode 0600, HTML escaping, and CSV formula neutralization.
- Made baseline comparison distinguish controls not observed in a partial report from controls removed from a complete assessment.
- Corrected firewall/LSM, effective SSH, PAM, account-file ownership/modes, and incomplete-probe classification without introducing kernel-version exploitability guesses.
- Corrected DNF4/5, YUM, Zypper, and pacman update adapters to use cached-only queries alongside APT. Empty cache results no longer imply a fully patched system; APT automatic-update assessment uses effective configuration and standard timer state.
- Added the source launcher and Debian 13 package build, retaining the existing PyInstaller Linux executable workflow and optional separately installed helper.
- Expanded regression and offscreen GUI coverage; CLI cancellation/deadline returns 130 and retains partial JSON output. Source and packaging versions now share one version definition.
- Corrected setup paths and documentation to reflect the existing GPLv3 license and management features. Credential and shell-history collection remain excluded.

## 0.6.0a1 (2026-10-19)

- Converted Kaotick Jay's LinFo v0.5 Bash system inventory and scan checks into modular Python.
- Added a PyQt6 desktop with findings, profile selection, inventory, reporting and guided hardening.
- Added 50 local hardening controls in the initial scanner, with explicit PASS/WARN/FAIL/UNKNOWN statuses.
- Added HTML, JSON, CSV report output, plus comparison against older JSON baselines.
- Added an optional root-owned PolicyKit helper for allowlisted, reversible sysctl settings.
- Removed offensive loot/credential search and avoided storing shell history or SSH key material.
- Added unit tests, CI workflow and CLI/headless execution for server deployment.

This initial port is an alpha milestone. Coverage and verification are not equivalent to a certified hardening benchmark.
