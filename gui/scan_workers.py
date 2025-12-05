# gui/scan_workers.py

import os
import threading
import psutil

from PyQt6.QtCore import QObject, pyqtSignal

from scanner.file_scanner import scan_file, scan_folder
from utils.analyzer import analyze_file
from utils.quarantine import quarantine_file
from scanner.autoscan import run_autoscan_scan
from scanner.system_scanner import KeyloggerDetector  # uses updated detector


class BaseScanWorker(QObject):
    """
    Base worker used by all scan workers.

    - logSignal(message, status)
    - progressSignal(0-100)
    - finishedSignal()
    - requestQuarantine(file_path)
    - requestKillProcess(image, pid)  (kept for backward compatibility; not used by new SystemScanWorker)
    """
    logSignal = pyqtSignal(str, str)        # message/file_path, status
    progressSignal = pyqtSignal(int)        # 0-100
    finishedSignal = pyqtSignal()
    requestQuarantine = pyqtSignal(str)     # file_path
    requestKillProcess = pyqtSignal(str, int)  # image, pid

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._action_event = threading.Event()
        self._last_action = False
        self._stop_flag = False

    # ----- user confirmation helpers (used by older process/system workers) -----
    def wait_for_user_action(self, timeout=None) -> bool:
        self._action_event.clear()
        fired = self._action_event.wait(timeout)
        return bool(fired) and bool(self._last_action)

    def set_user_action(self, value: bool):
        self._last_action = bool(value)
        self._action_event.set()

    # ----- cooperative stop (for Cancel button) -----
    def request_stop(self):
        self._stop_flag = True

    # alias used by dialogs that call request_cancel()
    def request_cancel(self):
        self.request_stop()

    @property
    def cancel_requested(self) -> bool:
        return self._stop_flag


# =====================================================================
# File scan worker
# =====================================================================

class FileScanWorker(BaseScanWorker):
    def __init__(self, file_paths, parent_dialog=None):
        super().__init__()
        self.file_paths = file_paths or []
        self.parent_dialog = parent_dialog

    def run(self):
        total = len(self.file_paths)
        if total == 0:
            self.logSignal.emit("No files provided to scan.", "info")
            self.finishedSignal.emit()
            return

        logged = set()
        for idx, fpath in enumerate(self.file_paths, start=1):
            if self._stop_flag:
                self.logSignal.emit("Scan aborted by user.", "info")
                break

            try:
                self.progressSignal.emit(int((idx - 1) / max(1, total) * 100))
            except Exception:
                pass

            try:
                ext = os.path.splitext(fpath)[1].lower()
                if ext in [".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tar.bz2"]:
                    # Archive → use scan_file engine
                    results = scan_file(fpath, quarantine_prompt=False)
                    for r in results:
                        fn = r.get("file", "Unknown")
                        if fn in logged:
                            continue
                        logged.add(fn)
                        status = r.get("status", "unknown")
                        self.logSignal.emit(fn, status)
                        if status == "suspicious":
                            self.requestQuarantine.emit(fn)
                else:
                    # Single normal file → analyzer
                    res = analyze_file(fpath, parent=None, ask_quarantine=False)
                    status = res.get("status", "unknown")
                    self.logSignal.emit(fpath, status)
                    if status == "suspicious":
                        self.requestQuarantine.emit(fpath)
            except Exception as e:
                self.logSignal.emit(f"{fpath} → ERROR: {e}", "error")

            try:
                self.progressSignal.emit(int(idx / max(1, total) * 100))
            except Exception:
                pass

        self.finishedSignal.emit()


# =====================================================================
# Folder scan worker
# =====================================================================

class FolderScanWorker(BaseScanWorker):
    def __init__(self, folder_path, recursive=True, parent_dialog=None):
        super().__init__()
        self.folder_path = folder_path
        self.recursive = recursive
        self.parent_dialog = parent_dialog

    def _handle(self, r, logged):
        if not isinstance(r, dict):
            return
        f = r.get("file", "Unknown")
        if f in logged:
            return
        logged.add(f)
        status = r.get("status", "unknown")
        self.logSignal.emit(f, status)
        if status == "suspicious":
            self.requestQuarantine.emit(f)

    def run(self):
        try:
            results = scan_folder(
                self.folder_path,
                recursive=self.recursive,
                quarantine_prompt=False
            )
            if results is None:
                results = []
            if not isinstance(results, list):
                results = [results]

            total = len(results) or 1
            logged = set()

            for idx, res in enumerate(results, start=1):
                if self._stop_flag:
                    self.logSignal.emit("Folder scan aborted by user.", "info")
                    break

                if isinstance(res, list):
                    for r in res:
                        self._handle(r, logged)
                else:
                    self._handle(res, logged)

                try:
                    self.progressSignal.emit(int(idx / max(1, total) * 100))
                except Exception:
                    pass

        except Exception as e:
            self.logSignal.emit(f"Folder scan error: {e}", "error")

        self.finishedSignal.emit()


# =====================================================================
# System / Process heuristic scan worker (uses KeyloggerDetector)
# =====================================================================

class SystemScanWorker(BaseScanWorker):
    """
    Heuristic system scanner using scanner.system_scanner.KeyloggerDetector.

    NEW BEHAVIOUR:
    - Runs full detection with skip_system_processes=True for speed.
    - Streams per-process log messages via logSignal.
    - Updates progress via progressSignal based on process count.
    - Emits:
        * highRiskSignal(list[dict])   → high/critical processes
        * fullReportSignal(dict)       → complete report
    - Does NOT kill processes directly and does NOT block waiting for user.
    """

    # extra signals used by SystemScannerDialog
    highRiskSignal = pyqtSignal(list)    # list[dict]
    fullReportSignal = pyqtSignal(dict)  # full report dict

    def __init__(self, sample_duration: float = 3.0, parent_dialog=None):
        super().__init__()
        self.parent_dialog = parent_dialog
        try:
            self.sample_duration = float(sample_duration)
        except Exception:
            self.sample_duration = 3.0

    def run(self):
        try:
            # announce
            self.logSignal.emit("--- Running heuristic system scan (processes) ---", "info")
            self.progressSignal.emit(0)

            # cooperative cancel hook
            def stop_cb() -> bool:
                return self.cancel_requested

            # forward logs to GUI
            def log_cb(msg: str):
                if self.cancel_requested:
                    return
                try:
                    self.logSignal.emit(msg, "info")
                except Exception:
                    pass

            # forward progress to GUI
            def progress_cb(pct: int):
                if self.cancel_requested:
                    return
                try:
                    self.progressSignal.emit(int(pct))
                except Exception:
                    pass

            # construct detector with callbacks
            detector = KeyloggerDetector(
                sample_duration=self.sample_duration,
                skip_system_processes=True,
                stop_callback=stop_cb,
                log_callback=log_cb,
                progress_callback=progress_cb,
            )

            # run detection
            report = detector.detect()

            if self.cancel_requested:
                self.logSignal.emit("System scan aborted by user.", "info")
            else:
                self.logSignal.emit("System scan completed.", "good")

            # extract high risk
            high_risk = report.get("high_risk", []) or []

            # push full report + high-risk to GUI
            try:
                self.fullReportSignal.emit(report)
            except Exception:
                pass

            try:
                self.highRiskSignal.emit(high_risk)
            except Exception:
                pass

            # ensure final progress is 100 when not cancelled
            try:
                if not self.cancel_requested:
                    self.progressSignal.emit(100)
            except Exception:
                pass

        except Exception as e:
            self.logSignal.emit(f"System scan error: {e}", "error")

        # always emit finished
        self.finishedSignal.emit()


# Backward-compat for old "ProcessScanWorker" name used by ScanPage
class ProcessScanWorker(SystemScanWorker):
    """
    Legacy alias: older UI expects ProcessScanWorker for 'Processes' scan type.
    Internally uses the same heuristic engine as SystemScanWorker.
    """
    def __init__(self, parent_dialog=None, sample_duration: float = 3.0):
        # parent_dialog as first positional keeps backward-compat
        super().__init__(sample_duration=sample_duration, parent_dialog=parent_dialog)


# =====================================================================
# AutoScan worker (headless, now in-memory only)
# =====================================================================

class AutoScanWorker(BaseScanWorker):
    """
    Headless autoscan worker:

    - Does NOT open any GUI window.
    - Does NOT write any autoscan log file to disk.
    - All logs are stored in memory by scanner.autoscan.
    - Still emits logSignal/progressSignal for live UI.
    """

    def __init__(self, folders, days, parent_dialog=None):
        super().__init__()

        # normalize folders list
        if folders is None:
            self.folders = []
        else:
            try:
                if isinstance(folders, str):
                    self.folders = [folders]
                else:
                    self.folders = list(folders)
            except Exception:
                self.folders = []

        # ensure days is a positive integer; fallback default 30
        try:
            days_val = int(days)
        except Exception:
            days_val = 30
        self.days = days_val if days_val > 0 else 30

        self.parent_dialog = parent_dialog
        # dedicated stop event for autoscan (scanner/autoscan.py checks .is_set())
        self._stop_event = threading.Event()

        # if no folders provided, use user defaults (Desktop, Downloads, Documents)
        if not self.folders:
            home = os.path.expanduser("~")
            self.folders = [
                os.path.join(home, "Desktop"),
                os.path.join(home, "Downloads"),
                os.path.join(home, "Documents"),
            ]

    def run(self):
        try:
            # High-level info to any live log listeners (e.g., console tab)
            self.logSignal.emit("--- AutoScan started ---", "info")

            # callback: propagate per-file status to UI logSignal
            def cb(file_path, status):
                try:
                    self.logSignal.emit(file_path, status)
                except Exception:
                    pass

            # callback: progress -> Qt signal
            def progress_cb(_, v):
                try:
                    self.progressSignal.emit(int(v))
                except Exception:
                    pass

            callbacks = {
                "log_callback": cb,
                "update_progress_safe": progress_cb,
                "complete_callback": lambda: None,
            }

            per_file_timeout = 15  # seconds per file

            run_autoscan_scan(
                self.folders,
                self.days,
                per_file_timeout,
                callbacks,
                self._stop_event,
            )

            # mark completion to any live listeners
            try:
                self.logSignal.emit("--- AutoScan finished ---", "info")
            except Exception:
                pass

        except Exception as e:
            self.logSignal.emit(f"AutoScan error: {e}", "error")
        finally:
            # defensive: emit finishedSignal only once to avoid races
            try:
                if not getattr(self, "_finished_emitted", False):
                    self._finished_emitted = True
                    self.finishedSignal.emit()
            except Exception:
                try:
                    self.finishedSignal.emit()
                except Exception:
                    pass
