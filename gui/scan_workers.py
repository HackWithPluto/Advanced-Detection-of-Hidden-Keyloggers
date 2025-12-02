# gui/scan_workers.py
import os
import threading
from PyQt6.QtCore import QObject, pyqtSignal
from scanner.file_scanner import scan_file, scan_folder
from utils.analyzer import analyze_file
from utils.quarantine import quarantine_file
from scanner.system_scanner import check_processes, kill_process
from scanner.autoscan import run_autoscan_scan


class BaseScanWorker(QObject):
    logSignal = pyqtSignal(str, str)        # file_path/text, status
    progressSignal = pyqtSignal(int)        # 0-100
    finishedSignal = pyqtSignal()
    requestQuarantine = pyqtSignal(str)     # file_path
    requestKillProcess = pyqtSignal(str, int)  # image, pid

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._action_event = threading.Event()
        self._last_action = False

    def wait_for_user_action(self, timeout=None):
        self._action_event.clear()
        fired = self._action_event.wait(timeout)
        return bool(fired) and bool(self._last_action)

    def set_user_action(self, value: bool):
        self._last_action = bool(value)
        self._action_event.set()


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
            if getattr(self, "_stop_flag", False):
                self.logSignal.emit("Scan aborted by user.", "info")
                break

            try:
                self.progressSignal.emit(int((idx - 1) / max(1, total) * 100))
            except Exception:
                pass

            try:
                ext = os.path.splitext(fpath)[1].lower()
                if ext in [".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tar.bz2"]:
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
            results = scan_folder(self.folder_path, recursive=self.recursive, quarantine_prompt=False)
            if results is None:
                results = []
            if not isinstance(results, list):
                results = [results]
            total = len(results) or 1
            logged = set()
            for idx, res in enumerate(results, start=1):
                if getattr(self, "_stop_flag", False):
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


class ProcessScanWorker(BaseScanWorker):
    def __init__(self, parent_dialog=None):
        super().__init__()
        self.parent_dialog = parent_dialog

    def run(self):
        try:
            self.logSignal.emit("--- Scanning system processes ---", "info")
            detected = check_processes("ioc.json")
            if not detected:
                self.logSignal.emit("No suspicious processes found.", "good")
                self.finishedSignal.emit()
                return

            total = len(detected)
            for idx, (image, pid) in enumerate(detected, start=1):
                if getattr(self, "_stop_flag", False):
                    self.logSignal.emit("Process scan aborted by user.", "info")
                    break
                self.logSignal.emit(image, "suspicious")
                self.requestKillProcess.emit(image, pid)
                try:
                    decision = self.wait_for_user_action(timeout=60)
                except Exception:
                    decision = False
                if decision:
                    result = kill_process([(image, pid)])
                    for _, (success, msg) in result.items():
                        self.logSignal.emit(f"{image} → {msg.strip()}", "info")
                else:
                    self.logSignal.emit(f"User declined to kill {image} (PID {pid})", "info")
                try:
                    self.progressSignal.emit(int(idx / max(1, total) * 100))
                except Exception:
                    pass
        except Exception as e:
            self.logSignal.emit(f"System scan error: {e}", "error")
        self.finishedSignal.emit()


class AutoScanWorker(BaseScanWorker):
    """
    Headless autoscan worker:
    - Does NOT open any GUI window.
    - Writes ONLY autoscan logs to database/logs/autoscan_logs.txt (fresh each run).
    - Still emits logSignal/progressSignal for debugging or future UI hooks.
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
                os.path.join(home, "Documents")
            ]

    def _map_status_to_result(self, status: str) -> str:
        """Same mapping for autoscan log file content."""
        try:
            s = (status or "").strip().lower()
            if s in ("suspicious", "detected", "malicious"):
                return "keylogger detected"
            if s in ("clean", "good", "ok"):
                return "normal file"
            return status
        except Exception:
            return status

    def run(self):
        try:
            self.logSignal.emit("--- AutoScan started ---", "info")

            # autoscan-specific log file (overwrite at start so each run is fresh)
            autoscan_log_path = os.path.join("database", "logs", "autoscan_logs.txt")
            os.makedirs(os.path.dirname(autoscan_log_path), exist_ok=True)
            with open(autoscan_log_path, "w", encoding="utf-8", errors="replace") as autoscan_fp:
                autoscan_fp.write(f"--- AutoScan run started ---\n")
                autoscan_fp.flush()

            # callback writes both to GUI signals and to the autoscan-specific log file
            def cb(file_path, status):
                try:
                    # emit UI/log signal for normal UI consumption
                    self.logSignal.emit(file_path, status)
                except Exception:
                    pass
                try:
                    result = self._map_status_to_result(status)
                    with open(autoscan_log_path, "a", encoding="utf-8", errors="replace") as autoscan_fp:
                        autoscan_fp.write(f"{file_path} → {result}\n")
                        autoscan_fp.flush()
                except Exception:
                    # never crash worker because logging failed
                    pass

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
                self._stop_event
            )

            # mark completion in autoscan log
            try:
                with open(autoscan_log_path, "a", encoding="utf-8", errors="replace") as autoscan_fp:
                    autoscan_fp.write("--- AutoScan run finished ---\n")
                    autoscan_fp.flush()
            except Exception:
                pass

        except Exception as e:
            self.logSignal.emit(f"AutoScan error: {e}", "error")
            try:
                autoscan_log_path = os.path.join("database", "logs", "autoscan_logs.txt")
                with open(autoscan_log_path, "a", encoding="utf-8", errors="replace") as autoscan_fp:
                    autoscan_fp.write(f"ERROR: {e}\n")
            except Exception:
                pass
        finally:
            # defensive: emit finishedSignal only once to avoid races
            try:
                if not getattr(self, "_finished_emitted", False):
                    self._finished_emitted = True
                    self.finishedSignal.emit()
            except Exception:
                # worst case: try to emit once more but swallow any errors
                try:
                    self.finishedSignal.emit()
                except Exception:
                    pass
