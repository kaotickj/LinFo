"""LinFo GUI and headless entry point."""
from __future__ import annotations
import argparse
import json
import sys
from . import __version__


def main() -> int:
    parser = argparse.ArgumentParser(description="LinFo local Linux hardening auditor")
    parser.add_argument("--cli", action="store_true", help="Run headlessly instead of opening PyQt6")
    parser.add_argument("--profile", choices=("workstation", "server"), default="workstation")
    parser.add_argument("--output", "-o", help="Export result to .json, .html or .csv")
    parser.add_argument("--compare", help="Compare this scan with prior LinFo JSON report (CLI mode)")
    parser.add_argument("--version", action="version", version=f"LinFo {__version__}")
    args = parser.parse_args()
    if args.cli:
        from .scanner import scan
        from .reports import export_report, compare_reports
        report = scan(args.profile, progress=lambda msg: print(msg, file=sys.stderr))
        if args.compare:
            with open(args.compare, "r", encoding="utf-8") as baseline:
                comparison = compare_reports(json.load(baseline), report)
            print(json.dumps(comparison, ensure_ascii=False, indent=2), file=sys.stderr)
        if args.output:
            export_report(report, args.output)
            print("Report saved:", args.output, file=sys.stderr)
        else:
            print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2))
        return 2 if any(f.status == "FAIL" and f.severity in ("critical", "high") for f in report.findings) else 0
    from .gui import launch
    return launch(args.profile)


if __name__ == "__main__":
    raise SystemExit(main())
