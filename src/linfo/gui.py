"""PyQt6 GUI. Never run the main application with root privileges."""
from __future__ import annotations
import json
import html
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from datetime import datetime
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QSignalBlocker, QTimer
from PyQt6.QtGui import QAction, QColor, QFont, QKeySequence, QIcon
from PyQt6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
                             QHeaderView, QLabel, QMainWindow, QMessageBox, QPlainTextEdit,
                             QProgressBar, QPushButton, QSplitter, QTabWidget, QTableWidget,
                             QTableWidgetItem, QVBoxLayout, QWidget, QInputDialog, QFrame, QLineEdit)
from . import __version__
from .checks import ACTION_LABELS
from .management import detect_platform, available_editors, actions_for, editor_command, ManagementAction
from .models import AuditReport, Finding
from .reports import export_report, compare_reports, load_report
from .scanner import scan

HELPER = "/usr/local/libexec/linfo-helper"


def helper_install_command() -> str:
    """Give packaged users the installed path and source users the existing path."""
    installed = Path("/usr/share/linfo/scripts/install-helper.sh")
    return f"sudo {installed}" if installed.is_file() else "sudo ./scripts/install-helper.sh"


STYLE = """
QWidget {background:#10171b; color:#e6f0ee; font-size:13px; font-family:DejaVu Sans, sans-serif;}
QLabel {background:transparent;}
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
QLineEdit {background:#16252a; color:#e6f0ee; border:1px solid #465b54; padding:8px 10px; border-radius:5px; selection-background-color:#34654c;}
QLineEdit:focus {border-color:#8deab5;} QHeaderView::section {font-size:11px; font-weight:600;}
QLabel#Session {background:#20362e; color:#b4e8c9; border:1px solid #395b4b; border-radius:6px; padding:8px 12px;}
QLabel#Muted {color:#9bafaa;} QPushButton#Primary {background:#8deab5; color:#112b20; font-weight:700; border:1px solid #8deab5;}
QPushButton#Primary:hover {background:#b2f4cf;} QPushButton#Primary:disabled {background:#263f33; color:#849d8b; border-color:#3f5746;}
QMenuBar {background:#10171b;} QMenu {background:#1b292e; border:1px solid #465b54;}
QMenu::item {padding:7px 22px;} QMenu::item:selected {background:#34654c;}
QTabBar::tab {margin-right:3px; border-top-left-radius:5px; border-top-right-radius:5px;}
QScrollBar:vertical {width:11px; background:#162125;} QScrollBar::handle:vertical {background:#456159; min-height:24px; border-radius:4px;}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {height:0;} QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {background:transparent;}
"""
STATUS_COLORS = {"FAIL": "#ff8e87", "WARN": "#f6ce7c", "PASS": "#9ce9bd", "INFO": "#b7d4fa", "UNKNOWN": "#bec0ca"}


class ScanWorker(QThread):
    done = pyqtSignal(object)
    progress = pyqtSignal(str)
    failed = pyqtSignal(str)
    finding_ready = pyqtSignal(object)

    def __init__(self, profile: str, parent=None):
        super().__init__(parent)
        self.profile = profile
        self.cancel_event = threading.Event()

    def run(self):
        try:
            self.done.emit(scan(self.profile, self.progress.emit,
                                cancel_event=self.cancel_event,
                                on_finding=self.finding_ready.emit))
        except Exception as exc:
            self.failed.emit(str(exc))


class ApplyWorker(QThread):
    done = pyqtSignal(object)

    def __init__(self, args: list[str], parent=None):
        super().__init__(parent)
        self.args = args

    def run(self):
        try:
            r = subprocess.run(["pkexec", HELPER, *self.args], capture_output=True,
                               text=True, errors="replace", timeout=420, stdin=subprocess.DEVNULL)
            self.done.emit((r.returncode, r.stdout[-4000:], r.stderr[-1800:]))
        except Exception as exc:
            self.done.emit((1, "", f"{type(exc).__name__}: {exc}"))


class MainWindow(QMainWindow):
    def __init__(self, profile: str | None = None):
        super().__init__()
        self.settings = QSettings("KaotickJay", "LinFo")
        self.report: AuditReport | None = None
        self._report_is_local = False
        self._closing = False
        self.system_platform = detect_platform()
        self.worker = None
        self.apply_worker = None
        self.setWindowTitle("LinFo | Linux Security Hardening")
        icon_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))
        icon_path = icon_root / "LinFo.png"
        if icon_path.is_file():
            self.setWindowIcon(QIcon(str(icon_path)))
        self.resize(1200, 780)
        self.setMinimumSize(1000, 680)
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
        chosen_profile = profile if profile in ("workstation", "server") else self.settings.value("assessment/profile", "workstation")
        self.profile.setCurrentText(chosen_profile if chosen_profile in ("workstation", "server") else "workstation")
        heading.addWidget(self.profile)
        self.scan_button = QPushButton("Run Security Assessment")
        self.scan_button.setObjectName("Primary")
        self.scan_button.clicked.connect(self.start_scan)
        heading.addWidget(self.scan_button)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        heading.addWidget(self.cancel_button)
        layout.addLayout(heading)
        self.session_label = QLabel()
        self.session_label.setObjectName("Session")
        self.session_label.setWordWrap(True)
        self.session_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.session_label)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        self._dashboard()
        self._findings()
        self._remediation()
        self._inventory()
        self._activity()
        self._export_tab()
        status = QHBoxLayout()
        self.status_label = QLabel("Ready. Read-only assessment; administrative credentials are not needed to open LinFo.")
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        status.addWidget(self.status_label, stretch=1)
        self.progress = QProgressBar()
        self.progress.setFixedWidth(180)
        self.progress.setFixedHeight(8)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        status.addWidget(self.progress)
        layout.addLayout(status)
        self._menu()
        self._restore_settings()
        self._update_controls()

    def _menu(self):
        menu = self.menuBar().addMenu("File")
        scan_action = QAction("New assessment", self)
        scan_action.setShortcut("F5")
        scan_action.triggered.connect(self.start_scan)
        menu.addAction(scan_action)
        self.scan_action = scan_action
        self.cancel_action = QAction("Cancel assessment", self)
        self.cancel_action.setShortcut("Esc")
        self.cancel_action.triggered.connect(self.cancel_scan)
        menu.addAction(self.cancel_action)
        self.open_action = QAction("Open JSON report…", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.triggered.connect(lambda: self.open_report())
        menu.addAction(self.open_action)
        export_action = QAction("Export report…", self)
        export_action.setShortcut(QKeySequence.StandardKey.Save)
        export_action.triggered.connect(self.save_report)
        menu.addAction(export_action)
        self.export_action = export_action
        search_action = QAction("Search findings", self)
        search_action.setShortcut(QKeySequence.StandardKey.Find)
        search_action.triggered.connect(self.focus_search)
        menu.addAction(search_action)
        help_menu = self.menuBar().addMenu("Help")
        about = QAction("About", self)
        about.triggered.connect(lambda: QMessageBox.information(self, "About LinFo", f"LinFo {__version__}\nOriginal tool and authorship: Kaotick Jay\nPyQt6 Linux hardening auditor\n\nLocal assessment with guided management, PolicyKit authorization, and sysctl rollback receipts.\n\nAssessment results describe observed controls; they do not certify the system as secure."))
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
        self.overview.setPlainText("Run an assessment to examine permissions, users, SSH, firewall, listening sockets, kernel controls, service monitoring and updates.\n\nFindings appear as checks finish. Search the evidence, review recommendations, and export or compare reports.\n\nThe Hardening tab retains the existing package, service, configuration-editor and sysctl management tools. Supported changes use explicit authorization; sysctl transactions include rollback receipts.")
        outer.addWidget(self.overview, stretch=1)
        self.tabs.addTab(tab, "Overview")

    def _findings(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        line = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search controls, evidence, paths, or recommendations…")
        self.search.setClearButtonEnabled(True)
        self.search.setAccessibleName("Search findings")
        self.search.textChanged.connect(self.refresh_findings)
        line.addWidget(self.search, stretch=1)
        self.filter = QComboBox()
        self.filter.addItems(["All", "FAIL", "WARN", "UNKNOWN", "PASS", "INFO"])
        self.filter.currentTextChanged.connect(self.refresh_findings)
        line.addWidget(self.filter)
        self.category_filter = QComboBox()
        self.category_filter.addItem("All categories")
        self.category_filter.currentTextChanged.connect(self.refresh_findings)
        line.addWidget(self.category_filter)
        layout.addLayout(line)
        self.finding_count = QLabel("No findings yet")
        self.finding_count.setObjectName("Muted")
        layout.addWidget(self.finding_count)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.findings = QTableWidget(0, 6)
        self.findings.setHorizontalHeaderLabels(["Status", "Severity", "Category", "Control", "Summary", "Manage"])
        self.findings.setAlternatingRowColors(True)
        self.findings.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.findings.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.findings.setSortingEnabled(True)
        self.findings.verticalHeader().setVisible(False)
        self.findings.verticalHeader().setDefaultSectionSize(42)
        self.findings.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.findings.setColumnWidth(0, 112)
        self.findings.setColumnWidth(1, 86)
        self.findings.setColumnWidth(2, 112)
        self.findings.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.findings.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.findings.setColumnWidth(5, 135)
        self.findings.itemSelectionChanged.connect(self.show_finding)
        splitter.addWidget(self.findings)
        detail_panel = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(0, 8, 0, 0)
        detail_heading = QHBoxLayout()
        detail_heading.addWidget(QLabel("Evidence and recommended action"))
        detail_heading.addStretch()
        self.copy_finding_button = QPushButton("Copy finding")
        self.copy_finding_button.setEnabled(False)
        self.copy_finding_button.clicked.connect(lambda: QApplication.clipboard().setText(self.detail.toPlainText()))
        detail_heading.addWidget(self.copy_finding_button)
        detail_layout.addLayout(detail_heading)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a finding to see its evidence, recommendation, and reference.")
        detail_layout.addWidget(self.detail)
        splitter.addWidget(detail_panel)
        splitter.setChildrenCollapsible(False)
        splitter.setSizes([360, 260])
        layout.addWidget(splitter)
        self.tabs.addTab(tab, "Findings")
        self.findings_tab = tab
        self.findings_splitter = splitter

    def _remediation(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.rem_intro = QLabel("Choose individual findings to install missing security tools, manage supported services, or edit configuration. Sysctl transactions create rollback receipts. Every privileged operation requires explicit authorization.")
        self.rem_intro.setWordWrap(True)
        layout.addWidget(self.rem_intro)
        editor_layout = QHBoxLayout()
        editor_layout.addWidget(QLabel("Configuration editor"))
        self.editor_choice = QComboBox()
        self._editors = available_editors()
        for editor_name, editor_path in self._editors:
            self.editor_choice.addItem(f"{editor_name} ({editor_path})", editor_path)
        if not self._editors:
            self.editor_choice.addItem("No graphical editor found")
        editor_layout.addWidget(self.editor_choice)
        editor_layout.addWidget(QLabel("System configuration"))
        self.config_choice = QComboBox()
        from .management import EDITABLE_CONFIGS
        for label, filename in EDITABLE_CONFIGS.items():
            self.config_choice.addItem(f"{label}: {filename}", filename)
        editor_layout.addWidget(self.config_choice)
        self.open_config_button = QPushButton("Open Configuration…")
        self.open_config_button.clicked.connect(lambda: self.open_configuration(self.config_choice.currentData()))
        editor_layout.addWidget(self.open_config_button)
        editor_layout.addStretch()
        layout.addLayout(editor_layout)
        self.action_table = QTableWidget(0, 3)
        self.action_table.setHorizontalHeaderLabels(["Select", "Action", "Affected controls"])
        self.action_table.setAlternatingRowColors(True)
        self.action_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.action_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.action_table)
        self.rem_note = QPlainTextEdit()
        self.rem_note.setReadOnly(True)
        self.rem_note.setMaximumHeight(125)
        self.rem_note.setPlainText(f"Privilege separation: run the GUI as your normal desktop user. Install the root-owned helper once with {helper_install_command()}. Changes will request authorization using PolicyKit (pkexec); configuration editing uses sudoedit in a terminal with your selected editor. Package installs and service changes are not automatically rollbackable. Firewall activation and SSH authentication changes require manual validation to prevent lockout.")
        layout.addWidget(self.rem_note)
        buttons = QHBoxLayout()
        self.apply_button = QPushButton("Review and Apply Selected")
        self.apply_button.clicked.connect(self.apply_selected)
        buttons.addWidget(self.apply_button)
        self.rollback_button = QPushButton("Rollback by Receipt ID…")
        self.rollback_button.clicked.connect(self.rollback)
        buttons.addWidget(self.rollback_button)
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

    def _activity(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("Live assessment and management activity"))
        self.activity = QPlainTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setMaximumBlockCount(3000)
        self.activity.setFont(QFont("DejaVu Sans Mono", 10))
        self.activity.setPlaceholderText("Progress and collection diagnostics appear here.")
        layout.addWidget(self.activity)
        self.tabs.addTab(tab, "Activity")
        self.activity_tab = tab

    def _export_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        heading = QLabel("Assessment report")
        heading.setStyleSheet("font-size:20px; font-weight:600")
        layout.addWidget(heading)
        description = QLabel("Save a self-contained HTML report, JSON, plain text, or findings CSV. Exports include the complete report even when the findings view is filtered. Reports contain host details such as interfaces and IPs.")
        description.setWordWrap(True)
        layout.addWidget(description)
        self.open_report_button = QPushButton("Open Saved JSON Report…")
        self.open_report_button.clicked.connect(lambda: self.open_report())
        layout.addWidget(self.open_report_button)
        self.save_report_button = QPushButton("Save Report…")
        self.save_report_button.clicked.connect(self.save_report)
        layout.addWidget(self.save_report_button)
        self.compare_button = QPushButton("Compare with a Saved JSON Baseline…")
        self.compare_button.clicked.connect(self.compare_baseline)
        layout.addWidget(self.compare_button)
        self.export_info = QPlainTextEdit()
        self.export_info.setReadOnly(True)
        self.export_info.setPlainText("Assessment reports never intentionally include private SSH keys, passwords, tokens, or shell history. They may still reveal sensitive network topology or usernames.")
        layout.addWidget(self.export_info)
        self.tabs.addTab(tab, "Reports")

    def start_scan(self):
        if self.worker is not None or self.apply_worker is not None:
            return
        self._report_is_local = True
        self.report = AuditReport(profile=self.profile.currentText(), inventory={})
        self.activity.clear()
        self.detail.clear()
        self.inventory_box.clear()
        self.overview.setPlainText("Collecting local evidence. Findings update as each control finishes.\n\nCancel keeps the evidence already collected in a partial report.")
        self.available_actions = []
        self.action_table.setRowCount(0)
        for widget in self.stats.values():
            widget.setText("—")
        with QSignalBlocker(self.category_filter):
            self.category_filter.clear()
            self.category_filter.addItem("All categories")
        self.refresh_findings()
        self.progress.setRange(0, 0)
        self.status_label.setText("Preparing…")
        self.worker = ScanWorker(self.profile.currentText(), self)
        self.worker.progress.connect(self.scan_progress)
        self.worker.finding_ready.connect(self.finding_received)
        self.worker.done.connect(self.scan_done)
        self.worker.failed.connect(self.scan_failed)
        self.worker.finished.connect(self.scan_finished)
        self._update_controls()
        self._save_settings()
        self.worker.start()

    def scan_done(self, report: AuditReport):
        self.report = report
        self.progress.setRange(0, 1)
        self.progress.setValue(0 if getattr(report, "cancelled", False) else 1)
        c = report.counts()
        for status, widget in self.stats.items():
            widget.setText(str(c[status]))
        self.overview.setPlainText(
            f"Host: {report.inventory.get('hostname')}\nOS: {report.inventory.get('operating_system')}\n"
            f"Kernel: {report.inventory.get('kernel')}\nProfile: {report.profile}\n"
            f"Distribution ID: {report.inventory.get('distribution_id')}\nPackage manager: {report.inventory.get('package_manager')}\nAdministrative group: {report.inventory.get('admin_group')}\n"
            f"Privilege: {'root' if report.inventory.get('root_privileges') else 'unprivileged (some checks may be UNKNOWN)'}\n\n"
            f"Controls assessed: {len(report.findings)}\nFailures: {c['FAIL']}\nWarnings: {c['WARN']}\n"
            f"Passed: {c['PASS']}\nUnknown: {c['UNKNOWN']}\nInformational: {c['INFO']}\n\n"
            + ("PARTIAL REPORT — this assessment was cancelled before all controls completed.\n\n"
               if getattr(report, "cancelled", False) else "")
            + ("Collection limits or probe errors are recorded in this report. Review affected evidence.\n\n"
               if getattr(report, "incomplete", False) else "")
            + "Unknown means the check could not establish a result. Validate findings in the context of your service requirements before remediating."
        )
        self.inventory_box.setPlainText(json.dumps(report.inventory, indent=2, ensure_ascii=False))
        self.refresh_findings()
        self.refresh_actions()
        state = "Assessment cancelled — partial report" if getattr(report, "cancelled", False) else "Assessment completed"
        self.status_label.setText(f"{state}: {len(report.findings)} controls")
        self._log(self.status_label.text())
        for error in getattr(report, "probe_errors", []):
            self._log("Collection note: " + str(error))
        self._update_controls()

    def scan_failed(self, error: str):
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.status_label.setText("Assessment failed")
        if self.report is not None:
            self.report.incomplete = True
            self.report.findings.append(Finding("gui.scan_error", "Scanner", "Assessment execution", "UNKNOWN", "medium", error,
                                                recommendation="Review Activity and retry the assessment."))
            self.refresh_findings()
        self._log("Assessment failed: " + error)
        self.tabs.setCurrentWidget(self.activity_tab)
        self._report_is_local = False

    def scan_progress(self, message: str):
        self.status_label.setText(message)
        self._log(message)

    def finding_received(self, finding: Finding):
        if self.report is None:
            return
        self.report.findings.append(finding)
        for status, widget in self.stats.items():
            widget.setText(str(self.report.counts()[status]))
        self._log(f"{finding.status} · {finding.title}: {finding.summary}")
        self.refresh_findings()

    def cancel_scan(self):
        if self.worker is None:
            return
        self.worker.cancel_event.set()
        self.cancel_button.setEnabled(False)
        self.cancel_action.setEnabled(False)
        self.status_label.setText("Cancelling assessment; preserving collected findings…")
        self._log("Cancellation requested.")

    def scan_finished(self):
        worker = self.worker
        self.worker = None
        if worker:
            worker.deleteLater()
        self._update_controls()
        if self._closing:
            QTimer.singleShot(0, self.close)

    def _log(self, message: str):
        self.activity.appendPlainText(datetime.now().strftime("%H:%M:%S") + "  " + message)

    def refresh_findings(self):
        if not self.report:
            self.findings.setRowCount(0)
            self.detail.clear()
            self.copy_finding_button.setEnabled(False)
            self.finding_count.setText("No findings yet")
            return
        selected = self.selected_finding()
        chosen_category = self.category_filter.currentText()
        categories = sorted({f.category for f in self.report.findings})
        with QSignalBlocker(self.category_filter):
            self.category_filter.clear()
            self.category_filter.addItems(["All categories", *categories])
            self.category_filter.setCurrentText(chosen_category if chosen_category in categories else "All categories")
        chosen = self.filter.currentText()
        category = self.category_filter.currentText()
        words = self.search.text().casefold().split()
        def matches(f):
            text = "\n".join((f.id, f.title, f.category, f.status, f.severity,
                               f.summary, f.evidence, f.recommendation, f.reference)).casefold()
            return ((chosen == "All" or f.status == chosen)
                    and (category == "All categories" or f.category == category)
                    and all(word in text for word in words))
        current = [f for f in self.report.findings if matches(f)]
        self.visible_findings = current
        with QSignalBlocker(self.findings):
            self.findings.setSortingEnabled(False)
            # A sorted QTableWidget can leave replaced cell widgets visible until
            # deferred deletion. Hide/remove them before rebuilding live rows.
            for row in range(self.findings.rowCount()):
                widget = self.findings.cellWidget(row, 5)
                if widget:
                    widget.hide()
                    self.findings.removeCellWidget(row, 5)
            self.findings.clearContents()
            self.findings.setRowCount(len(current))
            for i, f in enumerate(current):
                for j, value in enumerate((f.status, f.severity, f.category, f.title, f.summary)):
                    item = QTableWidgetItem(value)
                    item.setToolTip("<div>" + html.escape(value).replace("\n", "<br>") + "</div>")
                    if j == 0:
                        item.setForeground(QColor(STATUS_COLORS.get(f.status, "#ffffff")))
                        item.setData(Qt.ItemDataRole.UserRole, f)
                    self.findings.setItem(i, j, item)
                plans = actions_for(f, self.system_platform, installed=lambda name: shutil.which(name) is not None)
                btn = QPushButton("Manage…" if plans else "Review")
                btn.setProperty("management", bool(plans))
                btn.setEnabled(not plans or self._management_allowed())
                btn.clicked.connect(lambda _checked=False, item=f: self.manage_finding(item))
                self.findings.setCellWidget(i, 5, btn)
            self.findings.setSortingEnabled(True)
        self.finding_count.setText(f"Showing {len(current)} of {len(self.report.findings)} findings")
        if selected:
            for row in range(self.findings.rowCount()):
                item = self.findings.item(row, 0)
                candidate = item.data(Qt.ItemDataRole.UserRole) if item else None
                if candidate and candidate.id == selected.id:
                    self.findings.selectRow(row)
                    break
            else:
                self.findings.clearSelection()
        self.show_finding()

    def selected_finding(self):
        if not self.findings.selectionModel().hasSelection():
            return None
        item = self.findings.item(self.findings.currentRow(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def show_finding(self):
        f = self.selected_finding()
        self.copy_finding_button.setEnabled(f is not None)
        if f:
            self.detail.setPlainText(
                f"{f.title} [{f.id}]\n\nStatus: {f.status} | Severity: {f.severity}\n"
                f"Category: {f.category}\n\n{f.summary}\n\nEvidence:\n{f.evidence or 'None'}\n\n"
                f"Recommendation: {f.recommendation or 'Manual review'}\n"
                + (f"\nReference: {f.reference}" if f.reference else ""))
        else:
            self.detail.clear()

    def focus_search(self):
        self.tabs.setCurrentWidget(self.findings_tab)
        self.search.setFocus()

    def manage_finding(self, finding: Finding):
        plans = actions_for(finding, self.system_platform, installed=lambda name: shutil.which(name) is not None)
        if not plans:
            QMessageBox.information(self, "Manual assessment required",
                f"{finding.title} [{finding.id}]\n\n{finding.recommendation or finding.summary}\n\n"
                "This control does not have a verified safe automatic remediation yet. The GUI will never silently change security policy.")
            return
        if not self._guard_management():
            return
        labels = [p.label for p in plans]
        choice, ok = QInputDialog.getItem(self, f"Manage: {finding.title}",
                                          "Select an operation:", labels, 0, False)
        if not ok:
            return
        self.manage_action(plans[labels.index(choice)])

    def manage_action(self, action: ManagementAction):
        if not self._guard_management():
            return
        if action.category == 'editor':
            self.open_configuration(action.args[0])
            return
        if not self._helper_ready():
            QMessageBox.warning(self, "Administrator helper unavailable",
                "To manage packages and services, first install the privileged helper using:\n\n"
                f"{helper_install_command()}\n\n"
                "The normal-user GUI calls this root-owned helper through PolicyKit, which will prompt for authorization."
                " Ensure that your account is authorized through the distro's sudo/wheel or PolicyKit policy.")
            return
        warning = "\n\nIMPORTANT: Package and service operations may change system behavior. "
        if action.args[:2] == ('service', 'disable'):
            warning += "Disabling a service can affect monitoring, authentication, and applications."
        else:
            warning += "Review service dependencies, network access, and any upgrade or reboot requirements."
        response = QMessageBox.question(self, "Authorize system management",
            f"{action.label}\n\n{action.explanation}{warning}\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if response == QMessageBox.StandardButton.Yes:
            self.start_change(list(action.args))

    def open_configuration(self, path: str):
        if not self._guard_management():
            return
        editor = self.editor_choice.currentData()
        if not editor:
            QMessageBox.warning(self, "No editor found", "Install Kate, Mousepad, Gedit, or another supported graphical editor.")
            return
        response = QMessageBox.question(self, "Edit privileged configuration",
            f"Open {path} in {editor}?\n\nLinFo uses sudoedit. Your editor stays unprivileged, "
            "and sudo requests credentials in a terminal. Validate configuration syntax and keep a backup before saving. "
            "Editing SSH, PAM or sudoers incorrectly may lock you out.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if response != QMessageBox.StandardButton.Yes:
            return
        try:
            argv, environment = editor_command(path, editor)
            subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            self.status_label.setText(f"Editor launched: {path}. Review and save in the editor.")
        except Exception as exc:
            QMessageBox.warning(self, "Editor launch failed", str(exc))

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
        self.apply_button.setEnabled(self._management_allowed() and bool(needs))

    def _management_allowed(self) -> bool:
        return (os.geteuid() != 0 and self.worker is None and self.apply_worker is None
                and (self.report is None or (self._report_is_local and not getattr(self.report, "cancelled", False))))

    def _guard_management(self) -> bool:
        if self._management_allowed():
            return True
        if os.geteuid() == 0:
            self.status_label.setText("Management is disabled in a root GUI session. Start LinFo as your normal desktop user.")
        elif self.worker is not None or self.apply_worker is not None:
            self.status_label.setText("Wait for the current assessment or approved operation to finish.")
        else:
            self.status_label.setText("This report is for review. Run a fresh local assessment before managing this host.")
        return False

    def _update_controls(self):
        scanning = self.worker is not None
        applying = self.apply_worker is not None
        busy = scanning or applying
        self.scan_button.setEnabled(not busy)
        self.scan_action.setEnabled(not busy)
        self.profile.setEnabled(not busy)
        cancellable = scanning and not self.worker.cancel_event.is_set()
        self.cancel_button.setEnabled(cancellable)
        self.cancel_action.setEnabled(cancellable)
        self.open_action.setEnabled(not busy)
        self.open_report_button.setEnabled(not busy)
        ready_report = self.report is not None and not busy
        self.export_action.setEnabled(ready_report)
        self.save_report_button.setEnabled(ready_report)
        self.compare_button.setEnabled(ready_report)
        management = self._management_allowed()
        self.apply_button.setEnabled(management and bool(getattr(self, "available_actions", [])))
        self.rollback_button.setEnabled(management)
        self.open_config_button.setEnabled(management and bool(self._editors))
        self.action_table.setEnabled(management)
        for row in range(self.findings.rowCount()):
            button = self.findings.cellWidget(row, 5)
            if button and button.property("management"):
                button.setEnabled(management)
        if os.geteuid() == 0:
            text = "ROOT SESSION · Assessment only. Run LinFo as your normal desktop user to use guided management."
        elif scanning:
            text = "LOCAL ASSESSMENT · Reading host configuration. Results appear as controls finish."
        elif applying:
            text = "APPROVED OPERATION · The existing privileged helper is handling the selected change."
        elif self.report is not None and (not self._report_is_local or getattr(self.report, "cancelled", False)):
            text = "REVIEW-ONLY REPORT · Run a fresh local assessment to enable management of this host."
        else:
            text = "STANDARD USER SESSION · Assessment is read only. Guided changes use the existing authorization and rollback workflow."
        self.session_label.setText(text)

    def _helper_ready(self) -> bool:
        try:
            metadata = os.stat(HELPER, follow_symlinks=False)
            return (os.path.isfile(HELPER) and not os.path.islink(HELPER) and
                    metadata.st_uid == 0 and not metadata.st_mode & 0o022 and
                    os.access(HELPER, os.X_OK) and shutil.which("pkexec") is not None)
        except OSError:
            return False

    def apply_selected(self):
        if not self._guard_management():
            return
        selected = []
        for i, action in enumerate(getattr(self, "available_actions", [])):
            widget = self.action_table.cellWidget(i, 0)
            if isinstance(widget, QCheckBox) and widget.isChecked():
                selected.append(action)
        if not selected:
            QMessageBox.information(self, "No controls selected", "Select at least one remediation check box.")
            return
        if not self._helper_ready():
            QMessageBox.warning(self, "Privileged helper required", f"Install the root-owned helper using:\n\n  {helper_install_command()}\n\nThen launch LinFo as your normal user. PolicyKit (pkexec) is also required.")
            return
        details = "\n".join(f"• {ACTION_LABELS[key]}" for key in selected)
        yes = QMessageBox.question(self, "Confirm system changes", "Apply these changes and persist them under /etc/sysctl.d/?\n\n" + details +
                                   "\n\nA rollback receipt will be generated. This may affect debugging or network behavior. Continue?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        if yes == QMessageBox.StandardButton.Yes:
            self.start_change(["apply", *selected])

    def rollback(self):
        if not self._guard_management():
            return
        if not self._helper_ready():
            QMessageBox.warning(self, "Helper required", f"Install the root-owned helper with {helper_install_command()} and ensure pkexec is available before rollback.")
            return
        receipt, ok = QInputDialog.getText(self, "Rollback", "Enter the transaction UUID shown in the apply receipt:")
        if ok and receipt.strip():
            yes = QMessageBox.question(self, "Confirm rollback", "Restore the recorded sysctl configuration and runtime values for transaction " + receipt.strip() + "?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if yes == QMessageBox.StandardButton.Yes:
                self.start_change(["rollback", receipt.strip()])

    def start_change(self, args: list[str]):
        if not self._guard_management():
            return
        self.status_label.setText("Awaiting authorization / applying approved changes…")
        self._log("Starting explicitly approved operation: " + " ".join(args))
        self.apply_worker = ApplyWorker(args, self)
        self.apply_worker.done.connect(self.change_done)
        self.apply_worker.finished.connect(self.change_finished)
        self._update_controls()
        self.apply_worker.start()

    def change_done(self, result):
        returncode, stdout, stderr = result
        self._log("Management result: " + (stderr or stdout or str(returncode)))
        if returncode:
            self.status_label.setText("Change was cancelled or failed")
            QMessageBox.warning(self, "Change not completed", (stderr or stdout or "Not authorized")[-2000:])
        else:
            self.status_label.setText("Change completed; run a fresh assessment")
            self.export_info.setPlainText(stdout[-3500:] + "\n\nPreserve any rollback receipt ID. Run a fresh assessment to verify the result.")
            QMessageBox.information(self, "Change receipt: preserve this ID", stdout[-3500:] + "\n\nRun a fresh assessment to verify the result.")

    def change_finished(self):
        worker = self.apply_worker
        self.apply_worker = None
        if worker:
            worker.deleteLater()
        self._update_controls()

    def compare_baseline(self):
        if not self.report:
            QMessageBox.information(self, "No report", "Run a security assessment first.")
            return
        filename, _ = QFileDialog.getOpenFileName(self, "Select earlier LinFo JSON report", "", "LinFo JSON (*.json)")
        if not filename:
            return
        try:
            changes = compare_reports(load_report(filename).as_dict(), self.report)
            body = f"Changed controls: {changes['count']}\n\n" + "\n".join(
                f"{x['id']}: {x['was'] or '(new)'} → "
                f"{x['now'] or ('(not evaluated)' if x.get('change') == 'not_observed' else '(removed)')}"
                for x in changes["changes"])
            if changes.get("partial_current"):
                body += "\n\nCurrent report has incomplete coverage. A control not evaluated in this assessment has not been established as removed."
            if changes.get("partial_previous"):
                body += "\n\nThe saved baseline also has incomplete coverage; newly observed controls may simply have been absent from its collected scope."
            self.export_info.setPlainText(body)
            self.tabs.setCurrentIndex(self.tabs.count() - 1)
        except Exception as exc:
            QMessageBox.warning(self, "Comparison failed", str(exc))

    def save_report(self):
        if not self.report:
            QMessageBox.information(self, "No report", "Run a security assessment first.")
            return
        if self.worker is not None or self.apply_worker is not None:
            return
        filename, selected_filter = QFileDialog.getSaveFileName(self, "Export LinFo report", "linfo-audit",
                                                  "HTML report (*.html);;JSON report (*.json);;CSV findings (*.csv);;Plain text (*.txt)")
        if not filename:
            return
        if not Path(filename).suffix:
            suffix = ".json" if "JSON" in selected_filter else ".csv" if "CSV" in selected_filter else ".txt" if "text" in selected_filter else ".html"
            filename += suffix
            if Path(filename).exists():
                replace = QMessageBox.question(self, "Replace existing report?", f"Replace {filename}?",
                                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                               QMessageBox.StandardButton.No)
                if replace != QMessageBox.StandardButton.Yes:
                    return
        try:
            export_report(self.report, filename)
            self.status_label.setText(f"Exported {filename}")
        except Exception as exc:
            QMessageBox.critical(self, "Export error", str(exc))

    def open_report(self, filename=None):
        if self.worker is not None or self.apply_worker is not None:
            return
        if filename is None:
            filename, _ = QFileDialog.getOpenFileName(self, "Open LinFo JSON report", "", "LinFo JSON (*.json)")
        if not filename:
            return
        try:
            report = load_report(filename)
        except Exception as exc:
            QMessageBox.warning(self, "Could not open report", str(exc))
            return
        self._report_is_local = False
        if report.profile in ("workstation", "server"):
            self.profile.setCurrentText(report.profile)
        self.activity.clear()
        self.scan_done(report)
        self.status_label.setText(f"Opened {Path(filename).name} for review; no local management is enabled by this report.")
        self._log(self.status_label.text())
        self._update_controls()

    def _restore_settings(self):
        geometry = self.settings.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        splitter = self.settings.value("window/findings_splitter")
        if splitter is not None:
            self.findings_splitter.restoreState(splitter)
        status = self.settings.value("findings/status", "All")
        if self.filter.findText(status) >= 0:
            self.filter.setCurrentText(status)
        editor = self.settings.value("management/editor", "")
        index = self.editor_choice.findData(editor)
        if index >= 0:
            self.editor_choice.setCurrentIndex(index)

    def _save_settings(self):
        self.settings.setValue("window/geometry", self.saveGeometry())
        self.settings.setValue("window/findings_splitter", self.findings_splitter.saveState())
        self.settings.setValue("assessment/profile", self.profile.currentText())
        self.settings.setValue("findings/status", self.filter.currentText())
        self.settings.setValue("management/editor", self.editor_choice.currentData() or "")
        self.settings.sync()

    def closeEvent(self, event):
        if self.apply_worker is not None and self.apply_worker.isRunning():
            self.status_label.setText("An approved operation is still running. Wait for its result and receipt before closing.")
            event.ignore()
            return
        if self.worker is not None and self.worker.isRunning():
            self._closing = True
            self.cancel_scan()
            self.status_label.setText("Stopping the assessment before closing…")
            event.ignore()
            return
        self._save_settings()
        event.accept()


def launch(profile: str | None = None) -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    win = MainWindow(profile)
    app.setWindowIcon(win.windowIcon())
    win.show()
    return app.exec()


# Retain the established entry point while supporting callers using run_gui.
run_gui = launch
