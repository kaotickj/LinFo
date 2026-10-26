"""LinFo GUI and headless entry point."""
from __future__ import annotations
import argparse
import json
import signal
import sys
import threading
from . import __version__


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="LinFo local Linux hardening auditor")
    parser.add_argument("--cli", "--headless", action="store_true", help="Run headlessly instead of opening PyQt6")
    parser.add_argument("--profile", choices=("workstation", "server"), default=None)
    parser.add_argument("--output", "-o", help="Export result to .json, .html, .csv or .txt")
    parser.add_argument("--compare", help="Compare this scan with prior LinFo JSON report (CLI mode)")
    parser.add_argument("--version", action="version", version=f"LinFo {__version__}")
    parser.add_argument("--timeout", type=float, default=180.0, help="CLI total assessment budget in seconds (default: 180)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress CLI progress messages")
    args = parser.parse_args(argv)
    if args.cli:
        from .scanner import scan
        from .reports import export_report, compare_reports, load_report
        if not sys.platform.startswith("linux"):
            parser.error("Local assessment requires Linux")
        cancel = threading.Event()
        handlers = {}
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                handlers[sig] = signal.signal(sig, lambda *_: cancel.set())
        try:
            progress = None if args.quiet else lambda msg: print(msg, file=sys.stderr, flush=True)
            report = scan(args.profile or "workstation", progress=progress, cancel_event=cancel, timeout=args.timeout)
            if args.compare:
                comparison = compare_reports(load_report(args.compare).as_dict(), report)
                print(json.dumps(comparison, ensure_ascii=False, indent=2), file=sys.stderr)
            if args.output:
                export_report(report, args.output)
                if not args.quiet:
                    print("Report saved:", args.output, file=sys.stderr)
            else:
                print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2))
            if report.cancelled:
                return 130
            return 2 if any(f.status == "FAIL" and f.severity in ("critical", "high") for f in report.findings) else 0
        except (ValueError, OSError) as exc:
            print(f"LinFo: {exc}", file=sys.stderr)
            return 1
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    try:
        from .gui import launch
    except ModuleNotFoundError as exc:
        if not exc.name.startswith("PyQt6"):
            raise
        print("PyQt6 is missing. Install python3-pyqt6 using your distribution package manager, or install this project in a virtual environment. See README.md.", file=sys.stderr)
        return 1
    return launch(args.profile)


if __name__ == "__main__":
    raise SystemExit(main())
