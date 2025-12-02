from __future__ import annotations
"""
scanner/realtime_scanner_patched_confirm_only.py

Patched realtime scanner module that shows ONLY one modal MessageBox per detection:
  Yes/No "Delete this file now?" (blocking confirmation).

This variant REMOVES all file-based logging and rotating-log creation.
All logger calls remain in place but the logger is configured with a NullHandler
so no log files are created and no output is emitted by default.

Save as scanner/realtime_scanner_patched_confirm_only.py and run via:
  python -m scanner.realtime_scanner_patched_confirm_only
or import start_scanner() from your tool.
"""

import os
import sys
import time
import ctypes
import threading
import traceback
import logging
from typing import Callable, Optional, Set, List, Dict

# -----------------------
# (Removed file-based logging / RotatingFileHandler to avoid creating log files)
# -----------------------
logger = logging.getLogger("realtime_scanner_patched_confirm_only")
logger.setLevel(logging.INFO)
# Ensure no handlers performing file I/O are attached; use a NullHandler so calls are safe/no-op.
for h in list(logger.handlers):
    logger.removeHandler(h)
logger.addHandler(logging.NullHandler())

# -----------------------
# ReadDirectoryChangesW constants
# -----------------------
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010

FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

# -----------------------
# Robust analyzer import (search up for utils/analyzer.py). Uses stub if missing.
# -----------------------
analyze_file = None

def _make_analyzer_stub(simulate_keylogger: bool = True):
    def _stub(path, parent=None, ask_quarantine=False):
        name = os.path.basename(path or "").lower()
        if simulate_keylogger and "keylogger" in name:
            return {"status": "suspicious", "verdict": "Keylogger Detected", "file": path}
        return {"status": "clean", "verdict": "clean", "file": path}
    return _stub

# 1) try normal import
try:
    from utils.analyzer import analyze_file
except Exception:
    analyze_file = None

# 2) if not found, search up from this file for utils/analyzer.py and insert that root into sys.path
if analyze_file is None:
    try:
        this_file = os.path.abspath(__file__)
        search_dir = os.path.dirname(this_file)
        project_root = None
        for _ in range(6):
            candidate = os.path.join(search_dir, "utils", "analyzer.py")
            if os.path.isfile(candidate):
                project_root = search_dir
                break
            parent = os.path.dirname(search_dir)
            if not parent or parent == search_dir:
                break
            search_dir = parent
        if project_root:
            if project_root not in sys.path:
                sys.path.insert(0, project_root)
            try:
                from utils.analyzer import analyze_file
            except Exception:
                analyze_file = None
    except Exception:
        analyze_file = None

# 3) fallback stub (simulate_keylogger=True for testing)
if analyze_file is None:
    analyze_file = _make_analyzer_stub(simulate_keylogger=True)
    try:
        logger.info("ANALYZER NOT FOUND: running with stub analyze_file (simulate_keylogger=True)")
    except Exception:
        pass

# -----------------------
# Helper: topmost invisible owner window for MessageBox
# -----------------------
def _create_invisible_owner_window(title: str = "realtime_owner") -> int:
    try:
        class WNDCLASSEX(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_uint),
                ("style", ctypes.c_uint),
                ("lpfnWndProc", ctypes.c_void_p),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", ctypes.c_void_p),
                ("hIcon", ctypes.c_void_p),
                ("hCursor", ctypes.c_void_p),
                ("hbrBackground", ctypes.c_void_p),
                ("lpszMenuName", ctypes.c_wchar_p),
                ("lpszClassName", ctypes.c_wchar_p),
                ("hIconSm", ctypes.c_void_p)
            ]

        def _wndproc(hWnd, msg, wParam, lParam):
            return user32.DefWindowProcW(hWnd, msg, wParam, lParam)
        WNDPROC_TYPE = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, ctypes.c_uint, ctypes.c_int, ctypes.c_int)
        wndproc_c = WNDPROC_TYPE(_wndproc)

        class_name = f"RealtimeScannerOwner_{os.getpid()}_{int(time.time()*1000)}"
        hInstance = ctypes.windll.kernel32.GetModuleHandleW(None)

        wce = WNDCLASSEX()
        wce.cbSize = ctypes.sizeof(WNDCLASSEX)
        wce.style = 0
        wce.lpfnWndProc = ctypes.cast(wndproc_c, ctypes.c_void_p).value
        wce.cbClsExtra = 0
        wce.cbWndExtra = 0
        wce.hInstance = ctypes.c_void_p(hInstance)
        wce.hIcon = None
        wce.hCursor = None
        wce.hbrBackground = None
        wce.lpszMenuName = None
        wce.lpszClassName = class_name
        wce.hIconSm = None

        atom = user32.RegisterClassExW(ctypes.byref(wce))
        WS_POPUP = 0x80000000
        WS_EX_TOPMOST = 0x00000008
        hwnd = user32.CreateWindowExW(WS_EX_TOPMOST, class_name, title,
                                      WS_POPUP,
                                      -10000, -10000, 1, 1,
                                      0, 0, hInstance, None)
        if not hwnd:
            return 0
        user32.SetWindowPos(ctypes.c_void_p(hwnd), ctypes.c_void_p(-1), 0, 0, 0, 0, 0x0001 | 0x0002)
        return int(hwnd)
    except Exception:
        return 0

def _destroy_invisible_owner_window(hwnd: int) -> None:
    try:
        if hwnd:
            user32.DestroyWindow(ctypes.c_void_p(hwnd))
    except Exception:
        pass

def _messagebox_delete_confirm(title: str, message: str) -> bool:
    try:
        hwnd = _create_invisible_owner_window()
        try:
            MB_YESNO = 0x00000004
            MB_ICONWARNING = 0x00000030
            MB_TOPMOST = 0x00040000
            MB_SYSTEMMODAL = 0x00001000
            flags = MB_YESNO | MB_ICONWARNING | MB_TOPMOST | MB_SYSTEMMODAL
            res = user32.MessageBoxW(ctypes.c_void_p(hwnd), str(message), str(title), flags)
            return int(res) == 6
        finally:
            _destroy_invisible_owner_window(hwnd)
    except Exception:
        try:
            res = user32.MessageBoxW(0, str(message), str(title), 0x00000004 | 0x00000030)
            return int(res) == 6
        except Exception:
            return False

# -----------------------
# Analysis wrapper & behavior (CONFIRM-ONLY variant)
# -----------------------
_DEFAULT_SETTLE = 0.5
_DEFAULT_DEDUP = 1.0
_DEFAULT_SKIP = [
    r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)",
    "/usr", "/var", "/proc", "/sys", "/dev"
]

def _is_skipped(path: str, skip_list: List[str]) -> bool:
    if not path:
        return True
    p = os.path.abspath(path).lower()
    for s in (skip_list or _DEFAULT_SKIP):
        try:
            if p.startswith(os.path.abspath(s).lower()):
                return True
        except Exception:
            pass
    return False

def _analyze_and_act(path: str, settle: float, skip_list: List[str], force_detect: bool = False, confirm_only: bool = True) -> None:
    """
    Confirm-only behavior: only shows a single modal confirmation MessageBox per detection.
    If confirm_only is False you can extend this function to re-enable notifications.
    """
    try:
        if not os.path.isfile(path):
            return
        if _is_skipped(path, skip_list):
            return

        time.sleep(float(settle))
        if not os.path.exists(path):
            return

        if analyze_file is None:
            logger.info("Scanned (no analyzer): %s", path)
            return

        try:
            result = analyze_file(path, parent=None, ask_quarantine=False)
        except Exception as ex:
            logger.info("Scanned (analyzer error): %s | error=%s", path, str(ex))
            return

        verdict_text = ""
        if isinstance(result, dict):
            verdict_text = (result.get("verdict") or result.get("status") or "").strip()
        elif isinstance(result, str):
            verdict_text = result.strip()

        logger.info("Scanned: %s | verdict=%s", path, verdict_text or "clean")

        status_norm = (verdict_text or "").lower()
        if force_detect or status_norm in ("suspicious", "detected", "malicious") or "keylogger" in status_norm:
            display = verdict_text or "Keylogger Detected"
            short_path = path if len(path) < 200 else ("..." + path[-197:])
            msg = f"{display}\n\nFile: {short_path}\n\nDelete this file now?"

            # ---------- ONLY modal confirmation is shown ----------
            try:
                if _messagebox_delete_confirm("Threat detected", msg):
                    try:
                        if os.path.exists(path):
                            os.remove(path)
                            logger.info("Deleted by user: %s", path)
                            # final notification intentionally omitted
                        else:
                            logger.warning("Delete requested but file missing: %s", path)
                            # final notification intentionally omitted
                    except Exception:
                        logger.exception("Failed to delete file: %s", path)
                        # final notification intentionally omitted
                else:
                    logger.info("User cancelled delete: %s", path)
            except Exception:
                logger.exception("Popup/response error for %s", path)
    except Exception:
        logger.exception("Unexpected error while analyzing %s", path)

# -----------------------
# ReadDirectoryChangesW watcher
# -----------------------
class _Watcher(threading.Thread):
    def __init__(self, root: str, callback: Callable[[str], None], flags: int):
        super().__init__(daemon=True)
        self.root = os.path.abspath(root)
        self.callback = callback
        self.flags = flags
        self._stop = threading.Event()
        self._handle = None

    def _open(self):
        CreateFileW = kernel32.CreateFileW
        CreateFileW.restype = ctypes.c_void_p
        CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
        h = CreateFileW(self.root, FILE_LIST_DIRECTORY,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
        if h == INVALID_HANDLE_VALUE or h is None:
            return None
        return h

    def run(self):
        self._handle = self._open()
        if not self._handle:
            return
        BUFFER = 64 * 1024
        while not self._stop.is_set():
            try:
                buf = ctypes.create_string_buffer(BUFFER)
                bytes_ret = ctypes.c_ulong(0)
                ok = kernel32.ReadDirectoryChangesW(ctypes.c_void_p(self._handle), ctypes.byref(buf), BUFFER,
                                                    True, self.flags, ctypes.byref(bytes_ret), None, None)
                if not ok:
                    time.sleep(0.3)
                    continue
                raw = buf.raw[: bytes_ret.value]
                off = 0
                while off < len(raw):
                    if off + 12 > len(raw):
                        break
                    next_off = int.from_bytes(raw[off:off+4], "little")
                    action = int.from_bytes(raw[off+4:off+8], "little")
                    name_len = int.from_bytes(raw[off+8:off+12], "little")
                    name_start = off + 12
                    name_end = name_start + name_len
                    if name_end > len(raw):
                        break
                    name_bytes = raw[name_start:name_end]
                    try:
                        fname = name_bytes.decode("utf-16-le")
                    except Exception:
                        fname = name_bytes.decode("utf-8", errors="ignore")
                    full = os.path.join(self.root, fname)
                    # actions: 1 = added, 4 = renamed_from, 5 = renamed_to
                    if action in (1, 4, 5):
                        try:
                            threading.Thread(target=self.callback, args=(full,), daemon=True).start()
                        except Exception:
                            pass
                    if next_off == 0:
                        break
                    off += next_off
            except Exception:
                time.sleep(0.5)
        try:
            kernel32.CloseHandle(ctypes.c_void_p(self._handle))
        except Exception:
            pass

    def stop(self):
        self._stop.set()

# -----------------------
# Controller & API
# -----------------------
_controller: Optional["RealtimeController"] = None

class RealtimeController:
    def __init__(self, settle: float = _DEFAULT_SETTLE, skip: Optional[List[str]] = None, force_detect: bool = False, confirm_only: bool = True):
        self.settle = float(settle)
        self.skip = skip if skip is not None else _DEFAULT_SKIP
        self.force_detect = bool(force_detect)
        self.confirm_only = bool(confirm_only)
        self.watchers: Dict[str, _Watcher] = {}
        self._dedup: Set[str] = set()
        self._dedup_lock = threading.Lock()
        self._dedup_window = _DEFAULT_DEDUP

    def _list_drives(self) -> List[str]:
        drives: List[str] = []
        if sys.platform.startswith("win"):
            import string
            from ctypes import windll
            try:
                mask = windll.kernel32.GetLogicalDrives()
            except Exception:
                mask = 0
            for letter in string.ascii_uppercase:
                if mask & 1:
                    root = f"{letter}:/"
                    if os.path.exists(root):
                        drives.append(root)
                mask >>= 1
        else:
            drives = ["/"]
        return list({os.path.abspath(d) for d in drives})

    def _on_event(self, path: str) -> None:
        try:
            p = os.path.abspath(path)
        except Exception:
            return
        with self._dedup_lock:
            if p in self._dedup:
                return
            self._dedup.add(p)
        def _clear():
            time.sleep(self._dedup_window)
            with self._dedup_lock:
                self._dedup.discard(p)
        threading.Thread(target=_clear, daemon=True).start()
        # pass confirm_only flag here
        threading.Thread(target=_analyze_and_act, args=(p, self.settle, self.skip, self.force_detect, self.confirm_only), daemon=True).start()

    def start(self):
        roots = self._list_drives()
        flags = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_LAST_WRITE
        for r in roots:
            if _is_skipped(r, self.skip):
                continue
            if r in self.watchers:
                continue
            w = _Watcher(r, self._on_event, flags)
            self.watchers[r] = w
            w.start()
            logger.info("Started watcher on %s", r)
        threading.Thread(target=self._mount_loop, daemon=True).start()
        logger.info("Realtime scanner started (autorun)")

    def _mount_loop(self):
        while True:
            try:
                current = set(self._list_drives())
                for d in current:
                    if d not in self.watchers and not _is_skipped(d, self.skip):
                        w = _Watcher(d, self._on_event, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_CREATION)
                        self.watchers[d] = w
                        w.start()
                        logger.info("New mount watcher added: %s", d)
                time.sleep(3.0)
            except Exception:
                time.sleep(3.0)

    def stop(self):
        for w in list(self.watchers.values()):
            try:
                w.stop()
            except Exception:
                pass
        self.watchers.clear()
        logger.info("Realtime scanner stopped")

def start_scanner(settle: float = _DEFAULT_SETTLE, skip: Optional[List[str]] = None, force_detect: bool = False, confirm_only: bool = True) -> None:
    global _controller
    if _controller is not None:
        return
    _controller = RealtimeController(settle=settle, skip=skip, force_detect=force_detect, confirm_only=confirm_only)
    _controller.start()

def stop_scanner() -> None:
    global _controller
    if _controller is None:
        return
    try:
        _controller.stop()
    finally:
        _controller = None

if __name__ == "__main__":
    try:
        start_scanner()
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        stop_scanner()