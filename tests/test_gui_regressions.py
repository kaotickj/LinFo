"""Desktop regression tests. No administrative operations are executed."""
from __future__ import annotations
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

try:
    from PyQt6.QtCore import QSettings, QThread, Qt
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication, QMessageBox
    HAS_QT = True
except ImportError:
    HAS_QT = False

if HAS_QT:
    from linfo.gui import MainWindow, STYLE, helper_install_command
    from linfo.models import AuditReport, Finding
    from linfo.reports import export_report, load_report
    from linfo import __version__


@unittest.skipUnless(HAS_QT, "PyQt6 is not installed")
class GuiRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)
        cls.app.setStyle("Fusion")
        cls.app.setStyleSheet(STYLE)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.settings = QSettings(str(self.folder / "settings.ini"), QSettings.Format.IniFormat)
        self.settings_patch = patch("linfo.gui.QSettings", return_value=self.settings)
        self.settings_patch.start()
        self.uid_patch = patch("linfo.gui.os.geteuid", return_value=1000)
        self.uid_patch.start()
        self.window = MainWindow("workstation")
        self.window.show()

    def tearDown(self):
        if self.window.worker is not None:
            self.window.worker.cancel_event.set()
            self.window.worker.wait(2000)
        self.app.processEvents()
        self.window.close()
        self.app.processEvents()
        self.uid_patch.stop()
        self.settings_patch.stop()
        self.temp.cleanup()

    def wait_for(self, condition, seconds=3):
        end = time.monotonic() + seconds
        while not condition() and time.monotonic() < end:
            QTest.qWait(10)
        self.assertTrue(condition(), "Qt event did not complete within the timeout")

    def report(self):
        return AuditReport(profile="server", inventory={"hostname": "fixture-host", "operating_system": "Fixture Linux"}, findings=[
            Finding("sysctl.aslr", "Kernel", "Process ASLR", "WARN", "high", "Disabled", "kernel.randomize_va_space = 0", action_id="aslr"),
            Finding("net.socket", "Network", "Listening sockets", "INFO", "info", "Local fixture", '<img src="file:///never-read"> /tmp/fixture', recommendation="Inspect local socket use"),
            Finding("account.root", "Accounts", "UID zero accounts", "PASS", "high", "One local root account"),
        ])

    def set_local_report(self):
        self.window._report_is_local = True
        self.window.scan_done(self.report())

    def test_root_startup_is_nonblocking_and_management_disabled(self):
        self.window.close()
        with patch("linfo.gui.os.geteuid", return_value=0), patch("linfo.gui.QMessageBox.warning") as warning:
            self.window = MainWindow("workstation")
            self.window.show()
            self.assertFalse(warning.called)
            self.assertIn("ROOT SESSION", self.window.session_label.text())
            self.assertFalse(self.window.apply_button.isEnabled())
            self.assertFalse(self.window.rollback_button.isEnabled())
            self.assertFalse(self.window.open_config_button.isEnabled())
            self.assertFalse(self.window._guard_management())

    def test_live_scan_is_background_cancel_returns_partial(self):
        started = threading.Event()
        worker_threads = []
        current_thread = threading.get_ident()
        def collect(profile, progress=None, cancel_event=None, on_finding=None, **kwargs):
            worker_threads.append(threading.get_ident())
            report = AuditReport(profile=profile, inventory={"hostname": "fixture-host"})
            finding = Finding("fixture.live", "Fixture", "Live evidence", "INFO", "info", "Arrived before completion")
            report.findings.append(finding)
            progress("Collecting fixture")
            on_finding(finding)
            started.set()
            cancel_event.wait(timeout=2)
            report.cancelled = cancel_event.is_set()
            report.incomplete = report.cancelled
            return report
        with patch("linfo.gui.scan", side_effect=collect):
            self.window.start_scan()
            self.wait_for(lambda: started.is_set() and self.window.findings.rowCount() == 1)
            self.assertFalse(self.window.scan_button.isEnabled())
            self.assertFalse(self.window.apply_button.isEnabled())
            self.assertIn("Live evidence", self.window.activity.toPlainText())
            self.window.cancel_scan()
            self.wait_for(lambda: self.window.worker is None)
        self.assertNotEqual(worker_threads[0], current_thread)
        self.assertTrue(self.window.report.cancelled)
        self.assertEqual(len(self.window.report.findings), 1)
        self.assertTrue(self.window.save_report_button.isEnabled())
        self.assertTrue(self.window.scan_button.isEnabled())
        self.assertFalse(self.window._management_allowed())

    def test_close_cancels_scan_and_retains_thread_until_finish(self):
        started = threading.Event()
        def collect(profile, progress=None, cancel_event=None, on_finding=None, **kwargs):
            started.set()
            cancel_event.wait(timeout=2)
            return AuditReport(profile=profile, inventory={}, cancelled=cancel_event.is_set(), incomplete=True)
        with patch("linfo.gui.scan", side_effect=collect):
            self.window.start_scan()
            self.wait_for(started.is_set)
            self.window.close()
            self.assertTrue(self.window._closing)
            self.wait_for(lambda: self.window.worker is None)
            self.wait_for(lambda: not self.window.isVisible())
        self.assertTrue(self.window.report.cancelled)

    def test_search_sort_selection_and_full_report_export(self):
        self.set_local_report()
        self.window.search.setText("/tmp/fixture")
        self.assertEqual(self.window.findings.rowCount(), 1)
        self.window.findings.selectRow(0)
        self.assertIn('<img src="file:///never-read">', self.window.detail.toPlainText())
        target = self.folder / "report.json"
        with patch("linfo.gui.QFileDialog.getSaveFileName", return_value=(str(target), "JSON report (*.json)")):
            self.window.save_report()
        self.assertEqual(len(load_report(target).findings), 3)
        self.window.search.clear()
        self.window.findings.sortItems(3, Qt.SortOrder.DescendingOrder)
        self.window.findings.selectRow(0)
        title = self.window.findings.item(0, 3).text()
        self.assertTrue(self.window.detail.toPlainText().startswith(title))
        self.window.filter.setCurrentText("WARN")
        self.assertEqual(self.window.findings.rowCount(), 1)
        self.assertEqual(self.window.findings.item(0, 0).text(), "WARN")

    def test_imported_report_never_drives_local_management(self):
        target = self.folder / "foreign-report.json"
        export_report(self.report(), str(target))
        self.window.open_report(str(target))
        self.assertEqual(self.window.profile.currentText(), "server")
        self.assertFalse(self.window._report_is_local)
        self.assertFalse(self.window.apply_button.isEnabled())
        self.assertFalse(self.window.rollback_button.isEnabled())
        self.assertFalse(self.window._management_allowed())
        with patch("linfo.gui.subprocess.Popen") as popen, patch("linfo.gui.ApplyWorker") as apply_worker:
            self.window.open_configuration("/etc/ssh/sshd_config")
            self.window.start_change(["apply", "aslr"])
            self.assertFalse(popen.called)
            self.assertFalse(apply_worker.called)

    def test_existing_apply_and_rollback_routes_are_preserved(self):
        self.set_local_report()
        self.assertTrue(self.window.apply_button.isEnabled())
        self.window.action_table.cellWidget(0, 0).setChecked(True)
        with patch.object(self.window, "_helper_ready", return_value=True), \
                patch("linfo.gui.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes), \
                patch.object(self.window, "start_change") as start:
            self.window.apply_selected()
            start.assert_called_with(["apply", "aslr"])
            with patch("linfo.gui.QInputDialog.getText", return_value=("2dfaf60f-99f6-4358-8153-4070aa0f36f3", True)):
                self.window.rollback()
            start.assert_called_with(["rollback", "2dfaf60f-99f6-4358-8153-4070aa0f36f3"])

    def test_partial_comparison_does_not_call_unobserved_controls_removed(self):
        baseline = self.folder / "baseline.json"
        export_report(self.report(), str(baseline))
        partial = self.report()
        partial.findings = partial.findings[:1]
        partial.cancelled = True
        partial.incomplete = True
        self.window.scan_done(partial)
        with patch("linfo.gui.QFileDialog.getOpenFileName", return_value=(str(baseline), "LinFo JSON (*.json)")):
            self.window.compare_baseline()
        text = self.window.export_info.toPlainText()
        self.assertIn("(not evaluated)", text)
        self.assertNotIn("(removed)", text)
        self.assertIn("incomplete coverage", text)

    def test_helper_hint_matches_packaged_or_source_installation(self):
        with patch("linfo.gui.Path.is_file", return_value=True):
            self.assertEqual(helper_install_command(), "sudo /usr/share/linfo/scripts/install-helper.sh")
        with patch("linfo.gui.Path.is_file", return_value=False):
            self.assertEqual(helper_install_command(), "sudo ./scripts/install-helper.sh")

    def test_settings_keep_explicit_profile_and_about_uses_actual_version(self):
        self.window.profile.setCurrentText("server")
        self.window.filter.setCurrentText("WARN")
        self.window.close()
        self.window = MainWindow(None)
        self.assertEqual(self.window.profile.currentText(), "server")
        self.assertEqual(self.window.filter.currentText(), "WARN")
        self.window.close()
        self.window = MainWindow("workstation")
        self.assertEqual(self.window.profile.currentText(), "workstation")
        about = self.window.menuBar().actions()[1].menu().actions()[0]
        with patch("linfo.gui.QMessageBox.information") as information:
            about.trigger()
        self.assertIn(__version__, information.call_args.args[2])

    def test_close_does_not_destroy_or_interrupt_approved_operation(self):
        stopped = threading.Event()
        started = threading.Event()
        class ExistingOperation(QThread):
            def run(self):
                started.set()
                stopped.wait(2)
        worker = ExistingOperation(self.window)
        self.window.apply_worker = worker
        worker.finished.connect(self.window.change_finished)
        worker.start()
        self.wait_for(started.is_set)
        self.window.close()
        self.assertTrue(self.window.isVisible())
        self.assertTrue(worker.isRunning())
        self.assertIn("approved operation", self.window.status_label.text())
        stopped.set()
        self.wait_for(lambda: self.window.apply_worker is None)


if __name__ == "__main__":
    unittest.main()
