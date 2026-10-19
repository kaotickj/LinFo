# Changelog

## 0.6.0a1 (2026-10-19)

- Converted Kaotick Jay's LinFo v0.5 Bash system inventory and scan checks into modular Python.
- Added a PyQt6 desktop with findings, profile selection, inventory, reporting and guided hardening.
- Added 50 local hardening controls in the initial scanner, with explicit PASS/WARN/FAIL/UNKNOWN statuses.
- Added HTML, JSON, CSV report output, plus comparison against older JSON baselines.
- Added an optional root-owned PolicyKit helper for allowlisted, reversible sysctl settings.
- Removed offensive loot/credential search and avoided storing shell history or SSH key material.
- Added unit tests, CI workflow and CLI/headless execution for server deployment.

This initial port is an alpha milestone. Coverage and verification are not equivalent to a certified hardening benchmark.
