"""PyQt6 GUI. Never run the main application with root privileges."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
                             QHeaderView, QLabel, QMainWindow, QMessageBox, QPlainTextEdit,
                             QProgressBar, QPushButton, QSplitter, QTabWidget, QTableWidget,
                             QTableWidgetItem, QVBoxLayout, QWidget, QInputDialog, QFrame)
from .checks import ACTION_LABELS
from .models import AuditReport, Finding
from .reports import export_report, compare_reports
from .scanner import scan

HELPER = "/usr/local/libexec/linfo-helper"
STYLE = """
QWidget {background:#10171b; color:#e6f0ee; font-size:13px; font-family:DejaVu Sans, sans-serif;}
QMainWindow {background:#10171b;}
QTabWidget::pane {border:1px solid #30413d; padding:10px; background:#152024;}
QTabBar::tab {background:#1b292e; padding:10px 18px; color:#c2d0ce;}
QTabBar::tab:selected {background:#284239; color:#a8f6c7; border-bottom:2px solid #8deab5;}
QPushButton {background:#2a463c; border:1px solid #537e6c; padding:9px 15px; border-radius:6px;}
QPushButton:hover {background:#34654c;} QPushButton:disabled {background:#202c2b; color:#778d86;}
QComboBox {background:#223035; border:1px solid #465b54; padding:7px; border-radius:4px;}
QTableWidget {background:#162125; alternate-background-color:#1a282c; gridline-color:#2f403f; border:1px solid #3a514c;}
QTableWidget::item:selected {background:#285c48;} QHeaderView::section {background:#273832; padding:7px; border:1px solid #3b4e49;}
QPlainTextEdit {background:#18252a; border:1px solid #3d5550; color:#dbe7e5; padding:10px;}
QLabel#Title {font-size:28px; font-weight:700; color:#91e8b4;} QLabel#Subtitle {color:#9bafaa;}
QLabel#Stat {font-size:22px; font-weight:700;} QProgressBar {border:1px solid #415b52; border-radius:5px; text-align:center;}
QProgressBar::chunk {background:#74d99c;} QFrame#StatCard {background:#1b2c2a; border:1px solid #39534b; border-radius:7px;}
"""
STATUS_COLORS = {"FAIL": "#ff8e87", "WARN": "#f6ce7c", "PASS": "#9ce9bd", "INFO": "#b7d4fa", "UNKNOWN": "#bec0ca"}


class ScanWorker(QThread):
    done = pyqtSignal(object)
    progress = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, profile: str):
        super().__init__()
        self.profile = profile

    def run(self):
        try:
            self.done.emit(scan(self.profile, self.progress.emit))
        except Exception as exc:
            self.failed.emit(str(exc))


class ApplyWorker(QThread):
    done = pyqtSignal(object)

    def __init__(self, args: list[str]):
        super().__init__()
        self.args = args

    def run(self):
        try:
            r = subprocess.run(["pkexec", HELPER, *self.args], capture_output=True,
                               text=True, errors="replace", timeout=75, stdin=subprocess.DEVNULL)
            self.done.emit((r.returncode, r.stdout[-4000:], r.stderr[-1800:]))
        except Exception as exc:
            self.done.emit((1, "", f"{type(exc).__name__}: {exc}"))


class MainWindow(QMainWindow):
    def __init__(self, profile: str):
        super().__init__()
        self.report: AuditReport | None = None
        self.worker = None
        self.apply_worker = None
        self.setWindowTitle("LinFo | Linux Security Hardening")
        self.resize(1200, 780)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(22, 18, 22, 18)
        heading = QHBoxLayout()
        name = QLabel("LinFo")
        name.setObjectName("Title")
        heading.addWidget(name)
        subtitle = QLabel("Security Posture · Assessment · Guided Hardening")
        subtitle.setObjectName("Subtitle")
        heading.addWidget(subtitle)
        heading.addStretch()
        heading.addWidget(QLabel("Profile"))
        self.profile = QComboBox()
        self.profile.addItems(["workstation", "server"])
        self.profile.setCurrentText(profile)
        heading.addWidget(self.profile)
        self.scan_button = QPushButton("Run Security Assessment")
        self.scan_button.clicked.connect(self.start_scan)
        heading.addWidget(self.scan_button)
        layout.addLayout(heading)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        self._dashboard()
        self._findings()
        self._remediation()
        self._inventory()
        self._export_tab()
        status = QHBoxLayout()
        self.status_label = QLabel("Ready. Read-only assessment; administrative credentials are not needed to open LinFo.")
        status.addWidget(self.status_label, stretch=1)
        self.progress = QProgressBar()
        self.progress.setFixedWidth(180)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        status.addWidget(self.progress)
        layout.addLayout(status)
        self._menu()
        if os.geteuid() == 0:
            QMessageBox.warning(self, "Do not run GUI as root", "Run LinFo as your normal desktop user. The installed privileged helper handles specific approved operations.")
            self.apply_button.setEnabled(False)

    def _menu(self):
        menu = self.menuBar().addMenu("File")
        scan_action = QAction("New assessment", self)
        scan_action.triggered.connect(self.start_scan)
        menu.addAction(scan_action)
        export_action = QAction("Export report…", self)
        export_action.triggered.connect(self.save_report)
        menu.addAction(export_action)
        help_menu = self.menuBar().addMenu("Help")
        about = QAction("About", self)
        about.triggered.connect(lambda: QMessageBox.information(self, "About LinFo", "LinFo v0.6 alpha\nOriginal tool and authorship: Kaotick Jay\nPyQt6 Linux hardening auditor\n\nNo exploitability or compliance certification is implied."))
        help_menu.addAction(about)

    def _dashboard(self):
        tab = QWidget()
        outer = QVBoxLayout(tab)
        txt = QLabel("Host security at a glance")
        txt.setStyleSheet("font-size:20px; font-weight:600;")
        outer.addWidget(txt)
        stats = QHBoxLayout()
        self.stats: dict[str, QLabel] = {}
        for status in ("FAIL", "WARN", "PASS", "UNKNOWN"):
            card = QFrame()
            card.setObjectName("StatCard")
            card_layout = QVBoxLayout(card)
            t = QLabel(status)
            t.setStyleSheet(f"color:{STATUS_COLORS[status]};")
            value = QLabel("—")
            value.setObjectName("Stat")
            card_layout.addWidget(t)
            card_layout.addWidget(value)
            stats.addWidget(card)
            self.stats[status] = value
        outer.addLayout(stats)
        self.overview = QPlainTextEdit()
        self.overview.setReadOnly(True)
        self.overview.setPlainText("Run an assessment to examine permissions, users, SSH, firewall, listening sockets, kernel controls, service monitoring and updates.\n\nDangerous changes to SSH, firewalls and package state are intentionally guidance-only in this initial build.")
        outer.addWidget(self.overview, stretch=1)
        self.tabs.addTab(tab, "Overview")

    def _findings(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        line = QHBoxLayout()
        line.addWidget(QLabel("Status filter"))
        self.filter = QComboBox()
        self.filter.addItems(["All", "FAIL", "WARN", "UNKNOWN", "PASS", "INFO"])
        self.filter.currentTextChanged.connect(self.refresh_findings)
        line.addWidget(self.filter)
        line.addStretch()
        layout.addLayout(line)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.findings = QTableWidget(0, 5)
        self.findings.setHorizontalHeaderLabels(["Status", "Severity", "Category", "Control", "Summary"])
        self.findings.setAlternatingRowColors(True)
        self.findings.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.findings.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.findings.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.findings.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.findings.itemSelectionChanged.connect(self.show_finding)
        splitter.addWidget(self.findings)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        splitter.addWidget(self.detail)
        splitter.setSizes([510, 190])
        layout.addWidget(splitter)
        self.tabs.addTab(tab, "Findings")

    def _remediation(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.rem_intro = QLabel("Only narrow, reversible sysctl fixes can be applied automatically. Review each change before authorization.")
        self.rem_intro.setWordWrap(True)
        layout.addWidget(self.rem_intro)
        self.action_table = QTableWidget(0, 3)
        self.action_table.setHorizontalHeaderLabels(["Select", "Action", "Affected controls"])
        self.action_table.setAlternatingRowColors(True)
        self.action_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.action_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.action_table)
        self.rem_note = QPlainTextEdit()
        self.rem_note.setReadOnly(True)
        self.rem_note.setMaximumHeight(125)
        self.rem_note.setPlainText("No changes without explicit approval. Requires a root-owned helper installed to /usr/local/libexec/linfo-helper and PolicyKit (pkexec). Each application creates a rollback receipt.\n\nCAUTION: kernel debugging workflows may rely on unrestricted ptrace. Review network service requirements before applying redirect settings.")
        layout.addWidget(self.rem_note)
        buttons = QHBoxLayout()
        self.apply_button = QPushButton("Review and Apply Selected")
        self.apply_button.clicked.connect(self.apply_selected)
        buttons.addWidget(self.apply_button)
        rollback = QPushButton("Rollback by Receipt ID…")
        rollback.clicked.connect(self.rollback)
        buttons.addWidget(rollback)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.tabs.addTab(tab, "Hardening")

    def _inventory(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.inventory_box = QPlainTextEdit()
        self.inventory_box.setReadOnly(True)
        layout.addWidget(self.inventory_box)
        self.tabs.addTab(tab, "Inventory")

    def _export_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        heading = QLabel("Assessment report")
        heading.setStyleSheet("font-size:20px; font-weight:600")
        layout.addWidget(heading)
        layout.addWidget(QLabel("Save a self-contained HTML report, machine-readable JSON or findings CSV. These files contain host details such as interfaces and IPs; store them securely."))
        btn = QPushButton("Save Report…")
        btn.clicked.connect(self.save_report)
        layout.addWidget(btn)
        compare = QPushButton("Compare with a Saved JSON Baseline…")
        compare.clicked.connect(self.compare_baseline)
        layout.addWidget(compare)
        self.export_info = QPlainTextEdit()
        self.export_info.setReadOnly(True)
        self.export_info.setPlainText("Assessment reports never intentionally include private SSH keys, passwords, tokens, or shell history. They may still reveal sensitive network topology or usernames.")
        layout.addWidget(self.export_info)
        self.tabs.addTab(tab, "Reports")

    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        self.scan_button.setEnabled(False)
        self.progress.setRange(0, 0)
        self.status_label.setText("Preparing…")
        self.worker = ScanWorker(self.profile.currentText())
        self.worker.progress.connect(self.status_label.setText)
        self.worker.done.connect(self.scan_done)
        self.worker.failed.connect(self.scan_failed)
        self.worker.start()

    def scan_done(self, report: AuditReport):
        self.report = report
        self.scan_button.setEnabled(True)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        c = report.counts()
        for status, widget in self.stats.items():
            widget.setText(str(c[status]))
        self.overview.setPlainText(
            f"Host: {report.inventory.get('hostname')}\nOS: {report.inventory.get('operating_system')}\n"
            f"Kernel: {report.inventory.get('kernel')}\nProfile: {report.profile}\n"
            f"Privilege: {'root' if report.inventory.get('root_privileges') else 'unprivileged (some checks may be UNKNOWN)'}\n\n"
            f"Controls assessed: {len(report.findings)}\nFailures: {c['FAIL']}\nWarnings: {c['WARN']}\n"
            f"Passed: {c['PASS']}\nUnknown: {c['UNKNOWN']}\nInformational: {c['INFO']}\n\n"
            "Unknown is not safe. Validate findings in the context of your service requirements before remediating."
        )
        self.inventory_box.setPlainText(json.dumps(report.inventory, indent=2, ensure_ascii=False))
        self.refresh_findings()
        self.refresh_actions()
        self.status_label.setText(f"Assessment completed: {len(report.findings)} checks")

    def scan_failed(self, error: str):
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.scan_button.setEnabled(True)
        self.status_label.setText("Assessment failed")
        QMessageBox.critical(self, "Assessment failed", error)

    def refresh_findings(self):
        if not self.report:
            return
        chosen = self.filter.currentText()
        current = [f for f in self.report.findings if chosen == "All" or f.status == chosen]
        self.visible_findings = current
        self.findings.setRowCount(len(current))
        for i, f in enumerate(current):
            for j, value in enumerate((f.status, f.severity, f.category, f.title, f.summary)):
                item = QTableWidgetItem(value)
                if j == 0:
                    item.setForeground(QColor(STATUS_COLORS.get(f.status, "#ffffff")))
                self.findings.setItem(i, j, item)
        self.detail.clear()

    def show_finding(self):
        if not hasattr(self, "visible_findings"):
            return
        row = self.findings.currentRow()
        if 0 <= row < len(self.visible_findings):
            f = self.visible_findings[row]
            self.detail.setPlainText(
                f"{f.title} [{f.id}]\n\nStatus: {f.status} | Severity: {f.severity}\n"
                f"Category: {f.category}\n\n{f.summary}\n\nEvidence:\n{f.evidence or 'None'}\n\n"
                f"Recommendation: {f.recommendation or 'Manual review'}\n"
                + (f"\nReference: {f.reference}" if f.reference else ""))

    def refresh_actions(self):
        if not self.report:
            return
        needs: dict[str, list[Finding]] = {}
        for f in self.report.findings:
            if f.status in ("FAIL", "WARN") and f.action_id in ACTION_LABELS:
                needs.setdefault(f.action_id, []).append(f)
        self.available_actions = list(needs)
        self.action_table.setRowCount(len(needs))
        for i, (key, affected) in enumerate(needs.items()):
            check = QCheckBox()
            check.setObjectName(key)
            self.action_table.setCellWidget(i, 0, check)
            self.action_table.setItem(i, 1, QTableWidgetItem(ACTION_LABELS[key]))
            self.action_table.setItem(i, 2, QTableWidgetItem(", ".join(f.title for f in affected)))
        self.apply_button.setEnabled(os.geteuid() != 0 and bool(needs))

    def _helper_ready(self) -> bool:
        try:
            metadata = os.stat(HELPER, follow_symlinks=False)
            return (os.path.isfile(HELPER) and not os.path.islink(HELPER) and
                    metadata.st_uid == 0 and not metadata.st_mode & 0o022 and
                    os.access(HELPER, os.X_OK) and shutil.which("pkexec") is not None)
        except OSError:
            return False

    def apply_selected(self):
        selected = []
        for i, action in enumerate(getattr(self, "available_actions", [])):
            widget = self.action_table.cellWidget(i, 0)
            if isinstance(widget, QCheckBox) and widget.isChecked():
                selected.append(action)
        if not selected:
            QMessageBox.information(self, "No controls selected", "Select at least one remediation check box.")
            return
        if not self._helper_ready():
            QMessageBox.warning(self, "Privileged helper required", "Install the root-owned helper using:\n\n  sudo ./scripts/install-helper.sh\n\nThen launch LinFo as your normal user. PolicyKit (pkexec) is also required.")
            return
        details = "\n".join(f"• {ACTION_LABELS[key]}" for key in selected)
        yes = QMessageBox.question(self, "Confirm system changes", "Apply these changes and persist them under /etc/sysctl.d/?\n\n" + details +
                                   "\n\nA rollback receipt will be generated. This may affect debugging or network behavior. Continue?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        if yes == QMessageBox.StandardButton.Yes:
            self.start_change(["apply", *selected])

    def rollback(self):
        if not self._helper_ready():
            QMessageBox.warning(self, "Helper required", "Install the root-owned helper and pkexec before rollback.")
            return
        receipt, ok = QInputDialog.getText(self, "Rollback", "Enter the transaction UUID shown in the apply receipt:")
        if ok and receipt.strip():
            yes = QMessageBox.question(self, "Confirm rollback", "Restore the recorded sysctl configuration and runtime values for transaction " + receipt.strip() + "?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if yes == QMessageBox.StandardButton.Yes:
                self.start_change(["rollback", receipt.strip()])

    def start_change(self, args: list[str]):
        if self.apply_worker and self.apply_worker.isRunning():
            return
        self.apply_button.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.status_label.setText("Awaiting authorization / applying approved changes…")
        self.apply_worker = ApplyWorker(args)
        self.apply_worker.done.connect(self.change_done)
        self.apply_worker.start()

    def change_done(self, result):
        returncode, stdout, stderr = result
        self.scan_button.setEnabled(True)
        self.apply_button.setEnabled(True)
        if returncode:
            self.status_label.setText("Change was cancelled or failed")
            QMessageBox.warning(self, "Change not completed", (stderr or stdout or "Not authorized")[-2000:])
        else:
            self.status_label.setText("Change completed; run a fresh assessment")
            QMessageBox.information(self, "Change receipt: preserve this ID", stdout[-3500:] + "\n\nRun a fresh assessment to verify the result.")

    def compare_baseline(self):
        if not self.report:
            QMessageBox.information(self, "No report", "Run a security assessment first.")
            return
        filename, _ = QFileDialog.getOpenFileName(self, "Select earlier LinFo JSON report", "", "LinFo JSON (*.json)")
        if not filename:
            return
        try:
            if os.path.getsize(filename) > 20_000_000:
                raise ValueError("Baseline exceeds 20 MB")
            with open(filename, "r", encoding="utf-8") as handle:
                changes = compare_reports(json.load(handle), self.report)
            body = f"Changed controls: {changes['count']}\n\n" + "\n".join(
                f"{x['id']}: {x['was'] or '(new)'} → {x['now'] or '(removed)'}"
                for x in changes["changes"])
            self.export_info.setPlainText(body)
            self.tabs.setCurrentIndex(self.tabs.count() - 1)
        except Exception as exc:
            QMessageBox.warning(self, "Comparison failed", str(exc))

    def save_report(self):
        if not self.report:
            QMessageBox.information(self, "No report", "Run a security assessment first.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Export LinFo report", "linfo-audit.html",
                                                  "HTML report (*.html);;JSON report (*.json);;CSV findings (*.csv)")
        if not filename:
            return
        try:
            export_report(self.report, filename)
            self.status_label.setText(f"Exported {filename}")
        except Exception as exc:
            QMessageBox.critical(self, "Export error", str(exc))


def launch(profile: str) -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    win = MainWindow(profile)
    win.show()
    return app.exec()
