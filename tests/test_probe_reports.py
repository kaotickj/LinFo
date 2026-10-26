"""Regression tests for bounded IO, partial scans, and report-file handling."""
import csv
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from linfo.models import AuditReport, Finding
from linfo.probe import OUTPUT_LIMIT, Probe, ProbeCancelled
from linfo.reports import compare_reports, export_report, load_report, render_html
from linfo.scanner import scan


class ProbeTests(unittest.TestCase):
    def test_arguments_remain_literal_and_stdin_is_closed(self):
        literal = '$(not-a-command); "literal" | &'
        result = Probe().run(sys.executable, "-c", "import sys; print(sys.argv[1]); print(repr(sys.stdin.read()))", literal)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.out.splitlines(), [literal, "''"])

    def test_timeout_retains_bounded_output_without_success(self):
        result = Probe().run(sys.executable, "-u", "-c", "import time; print('started'); time.sleep(5)", timeout=.15)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)
        self.assertIn("started", result.out)

    def test_cancel_still_works_after_pipes_close(self):
        event = threading.Event()
        probe = Probe(cancel_event=event)
        timer = threading.Timer(.15, event.set)
        timer.start()
        start = time.monotonic()
        try:
            with self.assertRaises(ProbeCancelled):
                probe.run(sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(5)")
        finally:
            timer.cancel()
        self.assertLess(time.monotonic() - start, 2)

    def test_grandchild_pipe_does_not_outlive_timeout(self):
        code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)']); print('parent')"
        start = time.monotonic()
        result = Probe().run(sys.executable, "-u", "-c", code, timeout=.2)
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - start, 2)

    def test_output_limit_prevents_false_complete_result(self):
        probe = Probe()
        result = probe.run(sys.executable, "-c", f"print('x'*{OUTPUT_LIMIT + 10000})")
        self.assertEqual(len(result.out), OUTPUT_LIMIT)
        self.assertTrue(result.truncated)
        self.assertFalse(result.ok)
        self.assertTrue(probe.errors)

    def test_global_collection_notes_do_not_copy_command_diagnostics(self):
        probe = Probe()
        secret = "https://user:test-password@example.test/repo"
        result = probe.run(sys.executable, "-u", "-c",
                           "import sys,time; print(sys.argv[1],file=sys.stderr); time.sleep(5)", secret, timeout=.15)
        self.assertTrue(result.timed_out)
        self.assertNotIn("test-password", "\n".join(probe.errors))

    def test_cancel_checked_before_cached_result(self):
        probe = Probe()
        self.assertTrue(probe.run(sys.executable, "-c", "pass").ok)
        probe.cancel_event.set()
        with self.assertRaises(ProbeCancelled):
            probe.run(sys.executable, "-c", "pass")

    def test_fifo_and_oversized_file_are_not_evaluated(self):
        with tempfile.TemporaryDirectory() as temp:
            pipe = Path(temp) / "pipe"
            os.mkfifo(pipe)
            probe = Probe()
            self.assertIsNone(probe.read(pipe))
            text = Path(temp) / "text"
            text.write_text("a" * 30)
            self.assertIsNone(probe.read(text, 10))
            self.assertIn("size limit", probe.read_issues[str(text)])


class ReportTests(unittest.TestCase):
    def report(self):
        return AuditReport("workstation", {"hostname": "<test>"}, [
            Finding("test", "Network", "<script>alert(1)</script>", "INFO", "low", "=badformula()", "A&B")])

    def test_json_roundtrip_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "report.json"
            report = self.report()
            report.cancelled = report.incomplete = True
            export_report(report, file)
            restored = load_report(file)
            self.assertTrue(restored.cancelled)
            self.assertTrue(restored.incomplete)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            self.assertEqual(restored.findings[0], report.findings[0])

    def test_html_escapes_evidence_and_marks_partial_reports(self):
        report = self.report()
        report.cancelled = True
        output = render_html(report)
        self.assertNotIn("<script>alert", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertIn("partial assessment", output)

    def test_csv_neutralizes_formula_prefixes(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "report.csv"
            export_report(self.report(), file)
            with file.open() as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["summary"], "'=badformula()")

    def test_symlink_output_does_not_overwrite_target(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "original"
            target.write_text("keep")
            link = Path(temp) / "report.json"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                export_report(self.report(), link)
            self.assertEqual(target.read_text(), "keep")

    def test_import_rejects_fifo_and_invalid_records(self):
        with tempfile.TemporaryDirectory() as temp:
            pipe = Path(temp) / "pipe"
            os.mkfifo(pipe)
            with self.assertRaises(ValueError):
                load_report(pipe)
            file = Path(temp) / "bad.json"
            data = self.report().as_dict()
            data["findings"][0]["status"] = "probably fine"
            file.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                load_report(file)

    def test_cancelled_comparison_does_not_claim_removed_controls(self):
        report = self.report()
        report.cancelled = True
        previous = {"findings": [{"id": "missing", "status": "FAIL"}]}
        comparison = compare_reports(previous, report)
        row = next(r for r in comparison["changes"] if r["id"] == "missing")
        self.assertEqual(row["change"], "not_observed")
        self.assertTrue(comparison["partial_current"])

    def test_legacy_report_unknown_findings_imply_visibility_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "old.json"
            data = self.report().as_dict()
            data.pop("incomplete")
            data.pop("cancelled")
            data.pop("probe_errors")
            data["findings"][0]["status"] = "UNKNOWN"
            file.write_text(json.dumps(data))
            report = load_report(file)
            self.assertTrue(report.incomplete)
            self.assertTrue(compare_reports(report.as_dict(), self.report())["partial_previous"])


class ScanTests(unittest.TestCase):
    def test_cancel_returns_completed_findings(self):
        event = threading.Event()
        first = Finding("one", "Kernel", "First", "INFO", "info", "Observed")
        def inventory(probe, target):
            target["hostname"] = "fixture"
            return target
        with patch("linfo.scanner.inventory", side_effect=inventory), \
                patch("linfo.checks.sysctl_findings", return_value=iter([first])), \
                patch("linfo.checks.account_findings", side_effect=AssertionError("Must not run")):
            report = scan(cancel_event=event, on_finding=lambda finding: event.set())
        self.assertTrue(report.cancelled)
        self.assertTrue(report.incomplete)
        self.assertIn(first, report.findings)
        self.assertEqual(report.findings[-1].id, "scan.incomplete")

    def test_cancellation_during_inventory_keeps_partial_inventory(self):
        event = threading.Event()
        def inventory(probe, target):
            target["hostname"] = "fixture"
            event.set()
            probe.check_cancelled()
        with patch("linfo.scanner.inventory", side_effect=inventory):
            report = scan(cancel_event=event)
        self.assertEqual(report.inventory["hostname"], "fixture")
        self.assertTrue(report.cancelled)


if __name__ == "__main__":
    unittest.main()
