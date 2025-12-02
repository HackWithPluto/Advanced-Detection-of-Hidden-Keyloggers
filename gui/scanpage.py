# gui/scanpage.py
import os
import json
import time
import threading
from PyQt6.QtCore import Qt, QThread
from PyQt6.QtGui import QTextCursor, QFont
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QProgressBar, QPushButton,
    QMessageBox, QFileDialog, QTextEdit
)
from .resources import (
    COLOR_BG, COLOR_PANEL, COLOR_TEXT, COLOR_ACCENT,
    COLOR_BAD, COLOR_GOOD, COLOR_INFO, resource_path
)
from .scan_workers import FileScanWorker, FolderScanWorker, ProcessScanWorker, AutoScanWorker
from utils.quarantine import quarantine_file

# global stop control (used to abort worker loops)
from threading import Event
stop_event = Event()


class ScanPage(QDialog):
    """
    Scanning dialog that reuses workers (moved to QThread).
    Displays detection lines in format:
        <file path> → <result>
    where result is 'keylogger detected' or 'normal file'.
    """

    def __init__(self, parent, scan_type, paths=None, folders=None):
        super().__init__(parent)
        self.setWindowTitle("Scanning...")
        self.setModal(True)
        self.resize(900, 600)
        self.setStyleSheet(f"background-color:{COLOR_BG}; color:{COLOR_TEXT};")

        layout = QVBoxLayout(self)

        # store title label so callers can modify (e.g. show "USB Drive")
        self.title_label = QLabel(f"Scan Mode: {scan_type}")
        self.title_label.setStyleSheet(f"color:{COLOR_ACCENT}; font-size:22px;")
        layout.addWidget(self.title_label)

        # Terminal: QTextEdit so HTML coloring works
        self.terminal = QTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setStyleSheet(
            f"background-color:{COLOR_PANEL}; color:{COLOR_TEXT}; font-family: Consolas, 'Courier New', monospace; font-size:14px;"
        )
        layout.addWidget(self.terminal)

        # Progress bar
        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        # Close button
        b_close = QPushButton("Close")
        b_close.clicked.connect(self.close_scan)
        layout.addWidget(b_close)

        # Thread and worker
        self.thread = QThread()
        self.worker = self.create_worker(scan_type, paths, folders)

        # clear global stop flag before starting
        try:
            stop_event.clear()
        except Exception:
            pass

        # Move worker to thread and wire signals
        self.worker.moveToThread(self.thread)
        self.worker.logSignal.connect(self.add_log)
        self.worker.progressSignal.connect(self.progress.setValue)
        self.worker.requestQuarantine.connect(self._on_request_quarantine)
        self.worker.requestKillProcess.connect(self._on_request_killprocess)
        self.worker.finishedSignal.connect(self.finish_scan)
        self.worker.finishedSignal.connect(self.thread.quit)
        self.thread.finished.connect(self.thread.deleteLater)

        # Start thread
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def create_worker(self, scan_type, paths, folders):
        """Factory for workers. Accepts aliases like 'USB Drive' as folder scans."""
        st = (scan_type or "").strip().lower()

        # treat any of these as folder scans
        if st in ("folder", "usb drive", "usb", "external", "removable", "drive"):
            return FolderScanWorker(paths, True, self)

        if st == "file":
            return FileScanWorker(paths, self)
        elif st in ("processes", "process"):
            return ProcessScanWorker(self)
        elif st == "autoscan":
            # normalize folders input
            folders_safe = []
            if folders is None:
                folders_safe = []
            else:
                if isinstance(folders, str):
                    folders_safe = [folders]
                else:
                    try:
                        folders_safe = list(folders)
                    except Exception:
                        folders_safe = []

            # read config for days and defaults
            days = 30
            default_folders = []
            try:
                with open("config.json", "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                days = int(cfg.get("autoscan_window_days",
                                   cfg.get("auto_scan_days",
                                           cfg.get("auto_scan_interval_days", days))))
                default_folders = cfg.get("scan_folders_default", cfg.get("auto_scan_folders", []))
            except Exception:
                cfg = {}

            if not folders_safe and default_folders:
                expanded = []
                home = os.path.expanduser("~")
                for p in default_folders:
                    if not isinstance(p, str):
                        continue
                    p2 = p.replace("<USER_DESKTOP>", os.path.join(home, "Desktop"))
                    p2 = p2.replace("<USER_DOWNLOADS>", os.path.join(home, "Downloads"))
                    expanded.append(os.path.expanduser(p2))
                folders_safe = expanded

            return AutoScanWorker(folders_safe, days, self)
        else:
            raise ValueError("Invalid scan type")

    def _insert_full_colored_line(self, path: str, result: str):
        """
        Render entire monospace line colored:
          - keylogger detected -> COLOR_BAD (bold)
          - normal file -> COLOR_GOOD
          - info -> COLOR_INFO
        Format output as: <path> → <result>
        """
        try:
            import html as _html
            p = _html.escape(path)
            r = _html.escape(result)
            lower = (result or "").strip().lower()

            if "keylogger detected" in lower or "detected" in lower or "malicious" in lower:
                color = COLOR_BAD
                weight = "font-weight:bold;"
            elif "normal file" in lower or "clean" in lower or "good" in lower:
                color = COLOR_GOOD
                weight = ""
            elif result.strip().startswith("---") or "info" in lower:
                color = COLOR_INFO
                weight = ""
            else:
                color = COLOR_TEXT
                weight = ""

            html_line = (
                f"<pre style='margin:0; white-space:pre; font-family:Consolas, \"Courier New\", monospace; font-size:14px;'>"
                f"<span style='color:{color}; {weight}'>{p} → {r}</span>"
                f"</pre>"
            )
            try:
                self.terminal.insertHtml(html_line)
                self.terminal.insertPlainText("\n")
            except Exception:
                self.terminal.insertPlainText(f"{path} → {result}\n")
        except Exception:
            try:
                self.terminal.insertPlainText(f"{path} → {result}\n")
            except Exception:
                pass

    def add_log(self, text, status):
        """
        Unified formatting for all scans:
          - Map worker status to friendly result strings used by this keylogger tool.
          - Render full monospace line with single color.
        """
        try:
            st = (status or "").strip().lower()
            if st in ("suspicious", "detected", "malicious"):
                result = "keylogger detected"
            elif st in ("clean", "good", "ok"):
                result = "normal file"
            else:
                # if worker already outputs friendly result, use it; else fallback to raw status
                result = status if isinstance(status, str) else str(status)

            path = text
            # render full colored line
            self._insert_full_colored_line(path, result)

            # auto-scroll
            try:
                self.terminal.moveCursor(QTextCursor.MoveOperation.End)
            except Exception:
                pass

        except Exception:
            try:
                self.terminal.insertPlainText(f"{text} → {status}\n")
            except Exception:
                pass

    def finish_scan(self):
        """Called when worker emits finishedSignal."""
        try:
            self.terminal.insertPlainText("\n--- Scan Completed ---\n")
            self.progress.setValue(100)
        except Exception:
            pass

        # clear global stop_event (ready for next scans)
        try:
            stop_event.clear()
        except Exception:
            pass

        # try to stop thread cleanly if still running
        try:
            if hasattr(self, "thread") and self.thread.isRunning():
                # ask thread to quit and wait a moment
                self.thread.quit()
                self.thread.wait(1500)
        except Exception:
            pass

    def close_scan(self):
        """User requests to close the scan dialog — signal workers politely."""
        try:
            stop_event.set()
        except Exception:
            pass

        try:
            # set worker stop flag or stop-event if present
            if hasattr(self, "worker"):
                try:
                    setattr(self.worker, "_stop_flag", True)
                except Exception:
                    pass
                try:
                    if hasattr(self.worker, "_stop_event") and self.worker._stop_event is not None:
                        self.worker._stop_event.set()
                except Exception:
                    pass
        except Exception:
            pass

        try:
            if hasattr(self, "thread") and self.thread.isRunning():
                self.thread.quit()
                self.thread.wait(1500)
        except Exception:
            pass
        finally:
            try:
                stop_event.clear()
            except Exception:
                pass
            self.close()

    def _on_request_quarantine(self, file_path):
        """
        Show quarantine dialog with Keylogger wording.
        Do NOT log the user's decision; perform quarantine silently if user accepts.
        """
        reply = QMessageBox.question(
            self,
            "Keylogger detected — Quarantine file?",
            f"Keylogger detected:\n{file_path}\n\nQuarantine now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                quarantine_file(file_path, parent=None, ask_user=False)
            except Exception:
                pass
        # intentionally do not add terminal logs for the user's choice

    def _on_request_killprocess(self, image, pid):
        """
        Ask user about killing a process; do not log the user's decision.
        Worker will be unblocked by set_user_action(decision).
        """
        reply = QMessageBox.question(
            self,
            "Kill Process?",
            f"Terminate process?\n{image} (PID: {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        decision = (reply == QMessageBox.StandardButton.Yes)
        try:
            if hasattr(self, "worker"):
                self.worker.set_user_action(decision)
        except Exception:
            pass
        # intentionally do not log the user's choice here
