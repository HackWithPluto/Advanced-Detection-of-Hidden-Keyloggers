# gui/system_scanner_dialog.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
System Heuristic Keylogger Scanner — UPDATED

New Features:
 - Live per-process logging (every process scanned)
 - Progress percentage based on total process count
 - Skip Windows processes for speed
 - Buttons to export results:
      • Save JSON Report
      • Save CSV Report
 - High-risk table with selection
 - “Show Related Files” button
 - “Delete All Related Files” button
"""

from __future__ import annotations
from typing import Any, Dict, List

from PyQt6 import QtCore, QtGui, QtWidgets
from .scan_workers import SystemScanWorker


class SystemScannerDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)

        self.setWindowTitle("System Scanner")
        self.resize(900, 620)
        self.setMinimumSize(820, 550)

        # runtime state
        self._last_report: Dict[str, Any] | None = None
        self._thread: QtCore.QThread | None = None
        self._worker: SystemScanWorker | None = None
        self._scan_running: bool = False
        self._cancel_requested: bool = False
        self._scan_start_time: QtCore.QDateTime | None = None

        self._build_ui()
        self._connect_signals()

        # auto-refresh progress text
        self._progress_timer = QtCore.QTimer(self)
        self._progress_timer.setInterval(1000)
        self._progress_timer.timeout.connect(self._on_progress_tick)
    # ---------------------------------------------------------
    # UI BUILD
    # ---------------------------------------------------------
    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setSpacing(10)

        # TITLE
        title = QtWidgets.QLabel("Advanced System Scanner")
        title.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignVCenter)
        title.setFont(QtGui.QFont("Aldhabi", 26, QtGui.QFont.Weight.Bold))
        title.setStyleSheet("color: #00e5ff;")
        layout.addWidget(title)

        subtitle = QtWidgets.QLabel(
            "This scan analyzes running processes, startup entries, hidden behavior and system activity "
            "to detect potential keyloggers.\n"
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #cccccc; font-size: 13px;")
        layout.addWidget(subtitle)

        # -----------------------------------------------------
        # CONTROL BAR
        # -----------------------------------------------------
        controls = QtWidgets.QHBoxLayout()
        controls.setSpacing(12)

        self.start_btn = QtWidgets.QPushButton("Start Scan")
        self.start_btn.setFixedHeight(36)
        self.start_btn.setStyleSheet(self._btn_style_primary())

        self.cancel_btn = QtWidgets.QPushButton("Cancel")
        self.cancel_btn.setFixedHeight(36)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setStyleSheet(self._btn_style_secondary())

        # Sample duration spinbox
        self.sample_spin = QtWidgets.QDoubleSpinBox()
        self.sample_spin.setDecimals(1)
        self.sample_spin.setMinimum(0.5)
        self.sample_spin.setMaximum(20.0)
        self.sample_spin.setSingleStep(0.5)
        self.sample_spin.setValue(2.0)
        self.sample_spin.setSuffix(" s per process")
        self.sample_spin.setFixedWidth(160)

        # Export buttons
        self.json_btn = QtWidgets.QPushButton("Save JSON")
        self.json_btn.setFixedHeight(32)
        self.json_btn.setEnabled(False)
        self.json_btn.setStyleSheet(self._btn_style_accent())

        self.csv_btn = QtWidgets.QPushButton("Save CSV")
        self.csv_btn.setFixedHeight(32)
        self.csv_btn.setEnabled(False)
        self.csv_btn.setStyleSheet(self._btn_style_accent())

        # Related files buttons
        self.show_related_btn = QtWidgets.QPushButton("Show Related Files")
        self.show_related_btn.setFixedHeight(32)
        self.show_related_btn.setEnabled(False)
        self.show_related_btn.setStyleSheet(self._btn_style_secondary())

        self.delete_related_btn = QtWidgets.QPushButton("Delete All Related Files")
        self.delete_related_btn.setFixedHeight(32)
        self.delete_related_btn.setEnabled(False)
        self.delete_related_btn.setStyleSheet(self._btn_style_danger())

        # Progress bar
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setFixedHeight(20)

        controls.addWidget(self.start_btn)
        controls.addWidget(self.cancel_btn)
        controls.addSpacing(15)
        controls.addWidget(QtWidgets.QLabel("Duration:"))
        controls.addWidget(self.sample_spin)
        controls.addStretch(1)
        controls.addWidget(self.progress)

        layout.addLayout(controls)

        # -----------------------------------------------------
        # SECONDARY BUTTON BAR
        # -----------------------------------------------------
        sec = QtWidgets.QHBoxLayout()
        sec.setSpacing(12)

        sec.addWidget(self.json_btn)
        sec.addWidget(self.csv_btn)
        sec.addSpacing(20)
        sec.addWidget(self.show_related_btn)
        sec.addWidget(self.delete_related_btn)
        sec.addStretch(1)

        layout.addLayout(sec)

        # -----------------------------------------------------
        # SPLITTER: LOG VIEW + HIGH-RISK TABLE
        # -----------------------------------------------------
        splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        layout.addWidget(splitter, stretch=1)

        # LOG PANE
        log_widget = QtWidgets.QWidget()
        log_layout = QtWidgets.QVBoxLayout(log_widget)
        log_label = QtWidgets.QLabel("Scan Activity")
        log_label.setStyleSheet("color:#00e5ff; font-weight:bold;")

        self.log_view = QtWidgets.QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.NoWrap)
        self.log_view.setStyleSheet(
            "QTextEdit { background-color:#000; color:#e0e0e0; border:1px solid #00e5ff55; "
            "font-family: Consolas; font-size:11px; }"
        )

        log_layout.addWidget(log_label)
        log_layout.addWidget(self.log_view)
        splitter.addWidget(log_widget)

        # HIGH-RISK TABLE
        table_widget = QtWidgets.QWidget()
        table_layout = QtWidgets.QVBoxLayout(table_widget)
        table_label = QtWidgets.QLabel("High-Risk Processes")
        table_label.setStyleSheet("color:#00e5ff; font-weight:bold;")

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["PID", "Name", "Executable", "Score", "Severity"]
        )
        self.table.setSelectionBehavior(QtWidgets.QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)

        self.table.setStyleSheet(
            "QTableWidget { background-color:#000; color:#e0e0e0; border:1px solid #00e5ff55; "
            "gridline-color:#00e5ff33; font-size:11px; }"
        )

        table_layout.addWidget(table_label)
        table_layout.addWidget(self.table)
        splitter.addWidget(table_widget)

        splitter.setSizes([260, 360])

        # CLOSE BUTTON
        bottom = QtWidgets.QHBoxLayout()
        bottom.addStretch(1)

        self.close_btn = QtWidgets.QPushButton("Close")
        self.close_btn.setFixedHeight(32)
        self.close_btn.setStyleSheet(self._btn_style_secondary())
        bottom.addWidget(self.close_btn)

        layout.addLayout(bottom)

        # dialog background
        self.setStyleSheet("QDialog { background-color:#050710; }")
    # ---------------------------------------------------------
    # BUTTON STYLE HELPERS
    # ---------------------------------------------------------
    def _btn_style_primary(self):
        return """
            QPushButton {
                background-color: rgba(0,0,0,0.85);
                color: #00e5ff;
                border: 2px solid #00e5ff;
                border-radius: 12px;
                font-size: 16px;
                padding: 4px 18px;
            }
            QPushButton:hover {
                background-color: rgba(20,20,20,1);
                border-color: #00ffff;
            }
        """

    def _btn_style_secondary(self):
        return """
            QPushButton {
                background-color: rgba(40,40,40,0.9);
                color: #e0e0e0;
                border: 1px solid #777;
                border-radius: 10px;
                padding: 4px 14px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: rgba(60,60,60,1);
            }
        """

    def _btn_style_accent(self):
        return """
            QPushButton {
                background-color: rgba(0,50,60,0.9);
                color: #00e5ff;
                border: 1px solid #00e5ff;
                border-radius: 10px;
                padding: 4px 14px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: rgba(0,80,100,1);
            }
        """

    def _btn_style_danger(self):
        return """
            QPushButton {
                background-color: rgba(90,0,0,0.9);
                color: #ff5555;
                border: 1px solid #ff4444;
                border-radius: 10px;
                padding: 4px 14px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: rgba(130,0,0,1);
            }
        """

    # ---------------------------------------------------------
    # SIGNAL CONNECTIONS
    # ---------------------------------------------------------
    def _connect_signals(self):
        self.start_btn.clicked.connect(self._on_start_scan)
        self.cancel_btn.clicked.connect(self._on_cancel_scan)
        self.close_btn.clicked.connect(self.reject)

        self.json_btn.clicked.connect(self._save_json)
        self.csv_btn.clicked.connect(self._save_csv)

        self.show_related_btn.clicked.connect(self._on_show_related)
        self.delete_related_btn.clicked.connect(self._on_delete_related)

        # table row click updates buttons
        self.table.itemSelectionChanged.connect(self._on_row_selected)

    # ---------------------------------------------------------
    # LOG APPEND
    # ---------------------------------------------------------
    def _append_log(self, text: str, status: str = ""):
        color = "#cccccc"
        st = (status or "").lower()

        if st in ("error", "fail"):
            color = "#ff5555"
        elif st in ("good", "clean", "ok"):
            color = "#55ff55"
        elif st in ("warning", "warn", "suspicious"):
            color = "#ffcc55"

        timestamp = QtCore.QDateTime.currentDateTime().toString("hh:mm:ss")
        html = f'<span style="color:{color}">{timestamp} → {text}</span>'
        self.log_view.append(html)

        # autoscroll
        self.log_view.verticalScrollBar().setValue(
            self.log_view.verticalScrollBar().maximum()
        )

    # ---------------------------------------------------------
    # PROGRESS BAR TEXT REFRESH
    # ---------------------------------------------------------
    @QtCore.pyqtSlot()
    def _on_progress_tick(self):
        if not self._scan_running:
            if self._progress_timer.isActive():
                self._progress_timer.stop()
            return

        if self._scan_start_time is None:
            return

        elapsed = self._scan_start_time.msecsTo(
            QtCore.QDateTime.currentDateTime()
        ) // 1000
        v = self.progress.value()

        if self._cancel_requested:
            if v >= 100:
                self.progress.setFormat(f"Cancelled ({elapsed}s)")
            else:
                self.progress.setFormat(f"{v}% (cancelling… {elapsed}s)")
        else:
            if v >= 100:
                self.progress.setFormat(f"Completed ({elapsed}s)")
            else:
                self.progress.setFormat(f"{v}%  ({elapsed}s)")
    # ---------------------------------------------------------
    # UPDATE HIGH-RISK TABLE
    # ---------------------------------------------------------
    @QtCore.pyqtSlot(list)
    def _on_high_risk(self, processes: List[Dict[str, Any]]):
        self.table.setRowCount(0)
        if not processes:
            return

        for p in processes:
            basic = p.get("basic", {})
            risk = p.get("risk", {})

            pid = basic.get("pid", "")
            name = basic.get("name", "")
            exe = basic.get("exe", "")
            score = risk.get("score", 0)
            severity = (risk.get("severity") or "").lower()

            row = self.table.rowCount()
            self.table.insertRow(row)

            def item(v):
                it = QtWidgets.QTableWidgetItem(str(v))
                it.setFlags(it.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
                return it

            self.table.setItem(row, 0, item(pid))
            self.table.setItem(row, 1, item(name))
            self.table.setItem(row, 2, item(exe))
            self.table.setItem(row, 3, item(score))

            sev_item = item(severity)
            if severity == "critical":
                sev_item.setForeground(QtGui.QBrush(QtGui.QColor("#ff4444")))
            elif severity == "high":
                sev_item.setForeground(QtGui.QBrush(QtGui.QColor("#ff9933")))
            elif severity == "medium":
                sev_item.setForeground(QtGui.QBrush(QtGui.QColor("#ffdd44")))
            else:
                sev_item.setForeground(QtGui.QBrush(QtGui.QColor("#55ff55")))

            self.table.setItem(row, 4, sev_item)

        # enable export buttons after scan
        self.json_btn.setEnabled(True)
        self.csv_btn.setEnabled(True)

    # ---------------------------------------------------------
    # FULL REPORT
    # ---------------------------------------------------------
    @QtCore.pyqtSlot(dict)
    def _on_full_report(self, report: Dict[str, Any]):
        self._last_report = report

    # ---------------------------------------------------------
    # TABLE SELECTION HANDLER
    # ---------------------------------------------------------
    def _on_row_selected(self):
        if not self._last_report:
            self.show_related_btn.setEnabled(False)
            self.delete_related_btn.setEnabled(False)
            return

        row = self.table.currentRow()
        if row < 0:
            self.show_related_btn.setEnabled(False)
            self.delete_related_btn.setEnabled(False)
            return

        # row selected → enable features
        self.show_related_btn.setEnabled(True)
        self.delete_related_btn.setEnabled(True)

    # ---------------------------------------------------------
    # START SCAN
    # ---------------------------------------------------------
    def _on_start_scan(self):
        if self._worker is not None:
            QtWidgets.QMessageBox.warning(
                self, "Scan Running", "A scan is already running."
            )
            return

        self.log_view.clear()
        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.progress.setFormat("Starting…")

        self._last_report = None
        self._cancel_requested = False
        self._scan_running = True
        self._scan_start_time = QtCore.QDateTime.currentDateTime()

        sample_duration = float(self.sample_spin.value())

        # thread + worker
        self._thread = QtCore.QThread(self)
        self._worker = SystemScanWorker(sample_duration=sample_duration, parent_dialog=self)
        self._worker.moveToThread(self._thread)

        # --- connect worker signals ---
        self._worker.logSignal.connect(self._append_log)
        self._worker.progressSignal.connect(self.progress.setValue)
        self._worker.highRiskSignal.connect(self._on_high_risk)
        self._worker.fullReportSignal.connect(self._on_full_report)

        self._worker.finishedSignal.connect(self._on_scan_finished)
        self._worker.finishedSignal.connect(self._thread.quit)

        self._thread.finished.connect(self._cleanup_thread_worker)

        # UI state
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.sample_spin.setEnabled(False)

        self._thread.started.connect(self._worker.run)
        self._thread.start()
        self._progress_timer.start()

        self._append_log(f"Starting scan ({sample_duration:.1f}s per process)…", "info")

    # ---------------------------------------------------------
    # CANCEL SCAN
    # ---------------------------------------------------------
    def _on_cancel_scan(self):
        if not self._scan_running:
            return

        self._cancel_requested = True
        self.cancel_btn.setEnabled(False)

        self._append_log("Cancel requested by user.", "warning")

        try:
            if self._worker is not None:
                self._worker.request_cancel()
        except Exception:
            pass

    # ---------------------------------------------------------
    # SCAN FINISHED
    # ---------------------------------------------------------
    @QtCore.pyqtSlot()
    def _on_scan_finished(self):
        self._scan_running = False

        if self._progress_timer.isActive():
            self._progress_timer.stop()

        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.sample_spin.setEnabled(True)

        if self.progress.value() < 100 and not self._cancel_requested:
            self.progress.setValue(100)

        if self._cancel_requested:
            self.progress.setFormat("Cancelled")
            self._append_log("Scan cancelled.", "info")
        else:
            self.progress.setFormat("Completed")
            self._append_log("Scan complete.", "good")

    # ---------------------------------------------------------
    # CLEANUP
    # ---------------------------------------------------------
    @QtCore.pyqtSlot()
    def _cleanup_thread_worker(self):
        try:
            if self._worker is not None:
                self._worker.deleteLater()
        except Exception:
            pass
        self._worker = None

        try:
            if self._thread is not None:
                self._thread.deleteLater()
        except Exception:
            pass
        self._thread = None
     # ---------------------------------------------------------
    # SAVE JSON REPORT  (FULL REPORT)
    # ---------------------------------------------------------
    def _save_json(self):
        if not self._last_report:
            QtWidgets.QMessageBox.warning(self, "No Data", "Run a scan first.")
            return

        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save Full JSON Report",
            "system_scan_full.json",
            "JSON Files (*.json)",
        )
        if not path:
            return

        try:
            import json
            # self._last_report already contains:
            #  - summary
            #  - processes (all)
            #  - high_risk
            #  - persistence, scheduled_tasks, startup_entries
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._last_report, f, indent=2)
            QtWidgets.QMessageBox.information(
                self,
                "Saved",
                f"Full JSON report (all processes) saved:\n{path}",
            )
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self,
                "Error",
                f"Failed to save JSON report:\n{e}",
            )

        # ---------------------------------------------------------
    # SAVE CSV REPORT  (FULL REPORT, ALL PROCESSES + DETAILS)
    # ---------------------------------------------------------
    def _save_csv(self):
        if not self._last_report:
            QtWidgets.QMessageBox.warning(self, "No Data", "Run a scan first.")
            return

        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save Full CSV Report",
            "system_scan_full.csv",
            "CSV Files (*.csv)",
        )
        if not path:
            return

        try:
            import csv
            import json

            processes = self._last_report.get("processes", []) or []

            headers = [
                # BASIC
                "PID",
                "Name",
                "Executable",
                "Cmdline",
                "Username",
                "PPID",
                "ParentName",
                "CPUPercent",
                "MemoryInfo",

                # RISK
                "Severity",
                "Score",
                "RiskExplanations",

                # INDICATORS / HEURISTICS
                "HiddenWindowCount",
                "HasUser32Gdi",
                "HasWin32Hooks",
                "FrequentSuspiciousWrites",
                "ClipboardHeuristic",
                "ExfiltrationHeuristic",
                "ThreadInjectionHeuristic",
                "WriteBytesDelta",
                "WriteCountDelta",
                "NewConnCount",
                "RemoteEndpoints",

                # SIGNATURE
                "Signed",
                "Publisher",
                "SignatureMethod",

                # PATH & LOCATION
                "PathSuspicious",

                # RAW DETAILS (LISTS/STRUCTS – JSON or joined)
                "Modules",
                "OpenFiles",
                "ConnectionsJSON",
                "HiddenWindowsJSON",
            ]

            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)

                for p in processes:
                    basic = p.get("basic", {}) or {}
                    risk = p.get("risk", {}) or {}
                    indicators = p.get("indicators", {}) or {}
                    sig = p.get("signature", {}) or {}

                    modules = p.get("modules", []) or []
                    open_files = p.get("open_files", []) or []
                    connections = p.get("connections", []) or []
                    hidden_windows = p.get("hidden_windows", []) or []

                    io_stats = indicators.get("io_stats", {}) or {}
                    net_stats = indicators.get("net_stats", {}) or {}

                    # Flatten / stringify some complex fields
                    cmdline = " ".join(basic.get("cmdline") or [])
                    mem_info = basic.get("memory_info") or {}
                    mem_info_str = json.dumps(mem_info, ensure_ascii=False)

                    risk_expl = " | ".join(risk.get("explanations", []) or [])

                    remote_eps = net_stats.get("remote_endpoints") or []
                    remote_eps_str = " ; ".join(
                        f"{ip}:{port}" for ip, port in remote_eps
                    )

                    modules_str = " ; ".join(str(m) for m in modules)
                    open_files_str = " ; ".join(str(fpath) for fpath in open_files)

                    connections_json = json.dumps(connections, ensure_ascii=False)
                    hidden_windows_json = json.dumps(hidden_windows, ensure_ascii=False)

                    row = [
                        # BASIC
                        basic.get("pid"),
                        basic.get("name"),
                        basic.get("exe"),
                        cmdline,
                        basic.get("username"),
                        basic.get("ppid"),
                        basic.get("parent_name"),
                        basic.get("cpu_percent"),
                        mem_info_str,

                        # RISK
                        risk.get("severity"),
                        risk.get("score"),
                        risk_expl,

                        # INDICATORS
                        indicators.get("hidden_window_count"),
                        indicators.get("has_user32_gdi"),
                        indicators.get("has_win32_hooks"),
                        indicators.get("frequent_suspicious_writes"),
                        indicators.get("clipboard_heuristic"),
                        indicators.get("exfiltration_heuristic"),
                        indicators.get("thread_injection_heuristic"),
                        io_stats.get("write_bytes_delta"),
                        io_stats.get("write_count_delta"),
                        net_stats.get("new_conn_count"),
                        remote_eps_str,

                        # SIGNATURE
                        sig.get("signed"),
                        sig.get("publisher"),
                        sig.get("method"),

                        # PATH
                        p.get("path_suspicious"),

                        # RAW
                        modules_str,
                        open_files_str,
                        connections_json,
                        hidden_windows_json,
                    ]

                    writer.writerow(row)

            QtWidgets.QMessageBox.information(
                self,
                "Saved",
                f"Full CSV report (all processes, all details) saved:\n{path}",
            )

        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self,
                "Error",
                f"Failed to save CSV report:\n{e}",
            )

    # ---------------------------------------------------------
    # SHOW RELATED FILES (Open Files + Suspicious Files)
    # ---------------------------------------------------------
    def _on_show_related(self):
        row = self.table.currentRow()
        if row < 0 or not self._last_report:
            return

        pid = int(self.table.item(row, 0).text())

        # find process data
        pdata = None
        for p in self._last_report.get("processes", []):
            if p.get("basic", {}).get("pid") == pid:
                pdata = p
                break

        if not pdata:
            QtWidgets.QMessageBox.warning(self, "Error", "Process data missing.")
            return

        # collect related files (open files + suspicious)
        files = set()
        for f in pdata.get("open_files", []):
            files.add(f)

        # additional suspicious locations (AppData/Temp etc)
        exe = pdata.get("basic", {}).get("exe")
        if exe:
            from pathlib import Path
            parent = Path(exe).parent
            try:
                for child in parent.iterdir():
                    if child.is_file():
                        files.add(str(child))
            except Exception:
                pass

        # show window
        msg = QtWidgets.QMessageBox(self)
        msg.setWindowTitle("Related Files")
        msg.setIcon(QtWidgets.QMessageBox.Icon.Information)

        if files:
            msg.setText("Files possibly related to this process:\n\n" + "\n".join(files))
        else:
            msg.setText("No associated files detected.")

        msg.exec()

    # ---------------------------------------------------------
    # DELETE RELATED FILES
    # ---------------------------------------------------------
    def _on_delete_related(self):
        row = self.table.currentRow()
        if row < 0 or not self._last_report:
            return

        pid = int(self.table.item(row, 0).text())

        # find process data
        pdata = None
        for p in self._last_report.get("processes", []):
            if p.get("basic", {}).get("pid") == pid:
                pdata = p
                break

        if not pdata:
            QtWidgets.QMessageBox.warning(self, "Error", "Process data missing.")
            return

        # collect files again (same logic as show_related)
        files = set(pdata.get("open_files", []))

        exe = pdata.get("basic", {}).get("exe")
        if exe:
            from pathlib import Path
            parent = Path(exe).parent
            try:
                for child in parent.iterdir():
                    if child.is_file():
                        files.add(str(child))
            except Exception:
                pass

        if not files:
            QtWidgets.QMessageBox.information(self, "No Files", "No files to delete.")
            return

        confirm = QtWidgets.QMessageBox.question(
            self,
            "Delete Files?",
            "This will permanently delete ALL associated files.\n\nProceed?",
            QtWidgets.QMessageBox.StandardButton.Yes |
            QtWidgets.QMessageBox.StandardButton.No
        )

        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        # delete files
        deleted = []
        errors = []

        import os

        for f in files:
            try:
                os.remove(f)
                deleted.append(f)
            except Exception as e:
                errors.append(f"{f} → {e}")

        msg = "Deleted:\n" + "\n".join(deleted) if deleted else "No files deleted."
        if errors:
            msg += "\n\nErrors:\n" + "\n".join(errors)

        QtWidgets.QMessageBox.information(self, "Deletion Result", msg)

    # ---------------------------------------------------------
    # SAFE CLOSE (avoids QThread warnings)
    # ---------------------------------------------------------
    def closeEvent(self, event: QtGui.QCloseEvent):
        try:
            if self._scan_running:
                self._on_cancel_scan()

            if self._thread and self._thread.isRunning():
                self._thread.wait(8000)
        except Exception:
            pass

        super().closeEvent(event)
