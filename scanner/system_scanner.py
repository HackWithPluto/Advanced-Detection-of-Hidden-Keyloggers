#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
scanner/system_scanner.py  (UPDATED)

Windows heuristic keylogger detector for KeyDefender.

This updated version includes:
 - Process-by-process progress callbacks
 - Live per-process logging
 - Optimized loop structure (safe, no accuracy loss)
 - Compatible with SystemScanWorker & GUI
 - Fully backward-compatible structure
"""

import argparse
import csv
import datetime
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Callable

import psutil

# Optional registry access (Windows only)
try:
    import winreg  # type: ignore
except Exception:  # pragma: no cover
    winreg = None

# Optional pywin32 imports; all usage must be guarded.
try:
    import win32api  # type: ignore
    import win32con  # type: ignore
    import win32gui  # type: ignore
    import win32process  # type: ignore
    import win32security  # type: ignore
    import win32file  # type: ignore
except Exception:
    win32api = None
    win32con = None
    win32gui = None
    win32process = None
    win32security = None
    win32file = None

import ctypes
from ctypes import wintypes

# Optional project logger helpers (log_detection etc.)
try:
    from utils.logger import log_detection  # type: ignore
except Exception:
    def log_detection(*args, **kwargs):
        pass


# ------------------------
# Module-level logger
# ------------------------
LOGGER = logging.getLogger("system_scanner")
if not LOGGER.handlers:
    LOGGER.setLevel(logging.INFO)
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(_handler)


# =====================================================================
# ProcessCollector
# =====================================================================

class ProcessCollector:
    """Collects process metadata and persistence indicators on Windows."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or LOGGER

        from pathlib import Path as _PathAlias
        self.appdata = os.environ.get("APPDATA") or str(_PathAlias.home() / "AppData" / "Roaming")
        self.local_appdata = os.environ.get("LOCALAPPDATA") or str(_PathAlias.home() / "AppData" / "Local")
        self.programdata = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        self.temp = os.environ.get("TEMP") or os.environ.get("TMP") or r"C:\Windows\Temp"

    def _safe_process(self, pid: int) -> Optional[psutil.Process]:
        """Return a psutil.Process instance if accessible, else None."""
        try:
            return psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def iter_processes(self) -> List[int]:
        """Enumerate current process IDs."""
        try:
            return [p.pid for p in psutil.process_iter(attrs=[], ad_value=None)]
        except Exception:
            return [p.pid for p in psutil.process_iter()]

    def get_basic_info(self, pid: int) -> Dict[str, Any]:
        """Collect basic process information."""
        info: Dict[str, Any] = {
            "pid": pid,
            "name": None,
            "exe": None,
            "cmdline": [],
            "ppid": None,
            "parent_name": None,
            "username": None,
            "cpu_percent": None,
            "memory_info": None,
        }

        proc = self._safe_process(pid)
        if not proc:
            return info

        try:
            info["name"] = proc.name()
        except Exception:
            pass
        try:
            info["exe"] = proc.exe()
        except Exception:
            pass
        try:
            info["cmdline"] = proc.cmdline()
        except Exception:
            pass
        try:
            info["ppid"] = proc.ppid()
        except Exception:
            pass
        try:
            parent = proc.parent()
            info["parent_name"] = parent.name() if parent else None
        except Exception:
            pass
        try:
            info["username"] = proc.username()
        except Exception:
            pass
        try:
            info["cpu_percent"] = proc.cpu_percent(interval=None)
        except Exception:
            pass
        try:
            info["memory_info"] = proc.memory_info()._asdict()
        except Exception:
            pass

        return info

    def get_loaded_modules(self, pid: int) -> List[str]:
        """Return a list of loaded module/DLL paths for the given PID."""
        modules: List[str] = []
        proc = self._safe_process(pid)
        if not proc:
            return modules

        # psutil memory maps
        try:
            maps = proc.memory_maps()
            for m in maps:
                path = getattr(m, "path", None) or getattr(m, "addr", None)
                if path and isinstance(path, str):
                    modules.append(path)
        except Exception:
            pass

        # EnumProcessModules via ctypes/psapi
        try:
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if handle:
                try:
                    HMODULE_ARR = ctypes.c_void_p * 1024
                    hmods = HMODULE_ARR()
                    needed = ctypes.c_ulong()
                    if psapi.EnumProcessModules(handle, ctypes.byref(hmods), ctypes.sizeof(hmods), ctypes.byref(needed)):
                        count = int(needed.value // ctypes.sizeof(ctypes.c_void_p))
                        get_name = psapi.GetModuleFileNameExW if hasattr(psapi, "GetModuleFileNameExW") else None
                        for i in range(min(count, 1024)):
                            hmod = hmods[i]
                            if not hmod:
                                continue
                            if get_name:
                                buf = ctypes.create_unicode_buffer(260)
                                if get_name(handle, hmod, buf, 260):
                                    modules.append(buf.value)
                finally:
                    kernel32.CloseHandle(handle)
        except Exception:
            pass

        # Deduplicate
        seen = set()
        result: List[str] = []
        for m in modules:
            if m not in seen:
                seen.add(m)
                result.append(m)
        return result
    def get_open_files(self, pid: int) -> List[str]:
        """Return a list of open file paths for the given PID."""
        files: List[str] = []
        proc = self._safe_process(pid)
        if not proc:
            return files
        try:
            for f in proc.open_files():
                if f.path:
                    files.append(f.path)
        except Exception:
            pass
        return files

    def get_network_connections(self, pid: int) -> List[Dict[str, Any]]:
        """Return a list of network connections for the given PID."""
        conn_info: List[Dict[str, Any]] = []
        proc = self._safe_process(pid)
        if not proc:
            return conn_info
        try:
            for c in proc.net_connections(kind="inet"):
                entry = {
                    "fd": c.fd,
                    "family": int(c.family),
                    "type": int(c.type),
                    "laddr": getattr(c.laddr, "ip", None),
                    "lport": getattr(c.laddr, "port", None),
                    "raddr": getattr(c.raddr, "ip", None),
                    "rport": getattr(c.raddr, "port", None),
                    "status": c.status,
                }
                conn_info.append(entry)
        except Exception:
            pass
        return conn_info

    def _get_registry_values(self, root: Any, subkey: str) -> List[str]:
        """Utility to list values under a registry key."""
        results: List[str] = []
        if not winreg:
            return results
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        _name, data, _typ = winreg.EnumValue(k, i)
                        if isinstance(data, str):
                            results.append(data)
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass
        return results

    def get_registry_persistence(self) -> Dict[str, List[str]]:
        """Collect common registry-based persistence entries."""
        data: Dict[str, List[str]] = {
            "Run": [],
            "RunOnce": [],
            "PoliciesRun": [],
            "Services": [],
        }
        if not winreg:
            return data

        # Run keys
        try:
            data["Run"] += self._get_registry_values(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            )
            data["Run"] += self._get_registry_values(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            )
        except Exception:
            pass

        # RunOnce keys
        try:
            data["RunOnce"] += self._get_registry_values(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            )
            data["RunOnce"] += self._get_registry_values(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            )
        except Exception:
            pass

        # Policies Run
        try:
            data["PoliciesRun"] += self._get_registry_values(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            )
            data["PoliciesRun"] += self._get_registry_values(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            )
        except Exception:
            pass

        # Services → ImagePath extraction
        try:
            root = winreg.HKEY_LOCAL_MACHINE
            base = r"System\CurrentControlSet\Services"
            with winreg.OpenKey(root, base, 0, winreg.KEY_READ) as services_key:
                i = 0
                while True:
                    try:
                        svc_name = winreg.EnumKey(services_key, i)
                        i += 1
                    except OSError:
                        break

                    try:
                        with winreg.OpenKey(services_key, svc_name, 0, winreg.KEY_READ) as sk:
                            try:
                                image_path, _typ = winreg.QueryValueEx(sk, "ImagePath")
                                if isinstance(image_path, str):
                                    data["Services"].append(image_path)
                            except OSError:
                                pass
                    except OSError:
                        pass
        except OSError:
            pass

        return data

    def get_scheduled_tasks(self) -> List[str]:
        """Collect the executable paths or commands from Windows Scheduled Tasks."""
        commands: List[str] = []
        try:
            out = subprocess.check_output(
                ["schtasks", "/Query", "/FO", "LIST", "/V"],
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            for line in out.splitlines():
                if line.strip().startswith("Task To Run:"):
                    val = line.split(":", 1)[-1].strip()
                    if val:
                        commands.append(val)
        except Exception:
            pass
        return commands

    def get_startup_folder_entries(self) -> List[str]:
        """Return executable paths present in common startup folders."""
        entries: List[str] = []
        from pathlib import Path as _PathAlias
        candidates = [
            _PathAlias(self.appdata)
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "Startup",
            _PathAlias(self.programdata)
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "StartUp",
        ]
        for folder in candidates:
            try:
                if folder.exists() and folder.is_dir():
                    for child in folder.iterdir():
                        if child.is_file():
                            entries.append(str(child))
            except Exception:
                pass
        return entries

    def _get_file_attributes_hidden(self, path: str) -> Optional[bool]:
        """Return True if the file has the Hidden attribute set; None if undetermined."""
        try:
            GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
            GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
            GetFileAttributesW.restype = wintypes.DWORD
            attrs = GetFileAttributesW(path)
            if attrs == 0xFFFFFFFF:
                return None
            FILE_ATTRIBUTE_HIDDEN = 0x2
            return bool(attrs & FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            return None

    def is_suspicious_path(self, path: Optional[str]) -> bool:
        """Return True if the path resides in suspicious folders like AppData/Temp."""
        if not path:
            return False
        p = path.lower()

        suspicious_roots = [
            (self.appdata or "").lower(),
            (self.local_appdata or "").lower(),
            (self.programdata or "").lower(),
            (self.temp or "").lower(),
        ]

        try:
            if any(p.startswith(root) for root in suspicious_roots if root):
                return True
        except Exception:
            pass

        try:
            hidden = self._get_file_attributes_hidden(path)
            if hidden:
                return True
        except Exception:
            pass

        return False
    def get_hidden_windows(self, pid: int) -> List[Dict[str, Any]]:
        """Enumerate invisible/hidden top-level windows belonging to the process."""
        windows: List[Dict[str, Any]] = []

        def add_if_hidden(hwnd: int, owning_pid: int) -> None:
            try:
                title = ""
                visible = True
                if win32gui:
                    title = win32gui.GetWindowText(hwnd) or ""
                    visible = bool(win32gui.IsWindowVisible(hwnd))
                else:
                    GetWindowTextW = ctypes.windll.user32.GetWindowTextW
                    IsWindowVisible = ctypes.windll.user32.IsWindowVisible
                    buf = ctypes.create_unicode_buffer(260)
                    GetWindowTextW(hwnd, buf, 260)
                    title = buf.value
                    visible = bool(IsWindowVisible(hwnd))
                if not visible:
                    windows.append({"hwnd": int(hwnd), "title": title, "pid": owning_pid})
            except Exception:
                pass

        try:
            if win32gui:
                def enum_cb(hwnd, _extra):
                    try:
                        _, wpid = win32process.GetWindowThreadProcessId(hwnd)
                        if wpid == pid:
                            add_if_hidden(hwnd, wpid)
                    except Exception:
                        pass
                win32gui.EnumWindows(enum_cb, None)
            else:
                EnumWindows = ctypes.windll.user32.EnumWindows
                GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId

                @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
                def enum_proc(hwnd: int, lparam: int) -> bool:
                    pid_out = ctypes.c_ulong()
                    try:
                        GetWindowThreadProcessId(hwnd, ctypes.byref(pid_out))
                        if int(pid_out.value) == pid:
                            add_if_hidden(hwnd, int(pid_out.value))
                    except Exception:
                        pass
                    return True

                EnumWindows(enum_proc, 0)
        except Exception:
            pass

        return windows

    def get_signature_info(self, path: Optional[str]) -> Dict[str, Any]:
        """Return basic digital signature and publisher information for an executable."""
        result = {"signed": None, "publisher": None, "method": "unknown"}
        if not path:
            return result

        # Version info (publisher) via pywin32 if available
        try:
            if win32api:
                info = win32api.GetFileVersionInfo(path, "\\")
                str_info = win32api.VerQueryValue(info, r"\StringFileInfo\040904b0")
                if isinstance(str_info, dict):
                    publisher = str_info.get("CompanyName") or str_info.get("LegalCopyright")
                    if publisher:
                        result["publisher"] = publisher
                        result["method"] = "version_info"
        except Exception:
            pass

        # WinVerifyTrust for signature check
        try:
            WinVerifyTrust = ctypes.windll.wintrust.WinVerifyTrust

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", ctypes.c_ulong),
                    ("Data2", ctypes.c_ushort),
                    ("Data3", ctypes.c_ushort),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                          (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

            WTD_UI_NONE = 0x00000002
            WTD_REVOKE_NONE = 0x00000000
            WTD_CHOICE_FILE = 1
            WTD_STATEACTION_VERIFY = 0x00000001
            WTD_SAFER_FLAG = 0x00000100

            class WINTRUST_FILE_INFO(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", ctypes.c_ulong),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p),
                ]

            class WINTRUST_DATA(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", ctypes.c_ulong),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", ctypes.c_ulong),
                    ("fdwRevocationChecks", ctypes.c_ulong),
                    ("dwUnionChoice", ctypes.c_ulong),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ("dwStateAction", ctypes.c_ulong),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", ctypes.c_ulong),
                    ("dwUIContext", ctypes.c_ulong),
                ]

            wfi = WINTRUST_FILE_INFO()
            wfi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            wfi.pcwszFilePath = path
            wfi.hFile = None
            wfi.pgKnownSubject = None

            wtd = WINTRUST_DATA()
            wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            wtd.dwUIChoice = WTD_UI_NONE
            wtd.fdwRevocationChecks = WTD_REVOKE_NONE
            wtd.dwUnionChoice = WTD_CHOICE_FILE
            wtd.pFile = ctypes.pointer(wfi)
            wtd.dwStateAction = WTD_STATEACTION_VERIFY
            wtd.dwProvFlags = WTD_SAFER_FLAG

            rv = WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wtd))
            if rv == 0:
                result["signed"] = True
                result["method"] = "wintrust"
            else:
                result["signed"] = False
                result["method"] = "wintrust"
        except Exception:
            pass

        return result

    def collect_for_pid(self, pid: int) -> Dict[str, Any]:
        """Collect the full dataset for a single process."""
        basic = self.get_basic_info(pid)
        exe_path = basic.get("exe")

        return {
            "basic": basic,
            "modules": self.get_loaded_modules(pid),
            "open_files": self.get_open_files(pid),
            "connections": self.get_network_connections(pid),
            "hidden_windows": self.get_hidden_windows(pid),
            "signature": self.get_signature_info(exe_path),
            "path_suspicious": self.is_suspicious_path(exe_path),
        }
# =====================================================================
# BehaviorAnalyzer
# =====================================================================

class BehaviorAnalyzer:
    """Analyzes behavioral indicators of keylogging activity using defensive heuristics."""

    def __init__(self, collector: ProcessCollector, logger: Optional[logging.Logger] = None) -> None:
        self.collector = collector
        self.logger = logger or LOGGER

    def _has_any(self, items: List[str], names: List[str]) -> bool:
        """Return True if any of the names are present within item basenames."""
        lower_base = [os.path.basename(i).lower() for i in items]
        for n in names:
            if n.lower() in lower_base:
                return True
        return False

    def _token_has_sedebug(self, pid: int) -> Optional[bool]:
        """Return True if the process token has SeDebugPrivilege enabled; None if unknown."""
        try:
            if not win32security or not win32api or not win32con:
                return None

            proc_handle = win32api.OpenProcess(0x0400 | 0x0010, False, pid)
            token = win32security.OpenProcessToken(proc_handle, win32con.TOKEN_QUERY)
            privs = win32security.GetTokenInformation(token, win32security.TokenPrivileges)

            for luid, attr in privs:
                name = win32security.LookupPrivilegeName(None, luid)
                if name == "SeDebugPrivilege":
                    enabled = bool(attr & (win32con.SE_PRIVILEGE_ENABLED | win32con.SE_PRIVILEGE_ENABLED_BY_DEFAULT))
                    return enabled
        except Exception:
            return None
        return False

    def _sample_io_and_connections(
        self,
        proc: Optional[psutil.Process],
        duration: float = 3.0
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Sample write I/O and connection cadence over a short window."""
        io_stats = {"write_bytes_delta": 0, "write_count_delta": 0}
        net_stats = {"new_conn_count": 0, "remote_endpoints": set()}

        if not proc:
            return io_stats, net_stats

        try:
            io0 = proc.io_counters() if hasattr(proc, "io_counters") else None
            conns0 = proc.net_connections(kind="inet")
        except Exception:
            return io_stats, net_stats

        time.sleep(max(0.1, duration))

        try:
            io1 = proc.io_counters() if hasattr(proc, "io_counters") else None
            conns1 = proc.net_connections(kind="inet")
        except Exception:
            return io_stats, net_stats

        if io0 and io1:
            try:
                io_stats["write_bytes_delta"] = max(0, int(io1.write_bytes - io0.write_bytes))
                io_stats["write_count_delta"] = max(0, int(io1.write_count - io0.write_count))
            except Exception:
                pass

        try:
            set0 = {(c.raddr.ip, c.raddr.port) for c in conns0 if c.raddr and c.raddr.ip}
            set1 = {(c.raddr.ip, c.raddr.port) for c in conns1 if c.raddr and c.raddr.ip}
            net_stats["new_conn_count"] = max(0, len(set1 - set0))
            net_stats["remote_endpoints"] = set1
        except Exception:
            pass

        return io_stats, net_stats

    def analyze(self, pdata: Dict[str, Any], sample_duration: float = 3.0) -> Dict[str, Any]:
        """Analyze a single process dataset and return indicator flags."""
        basic = pdata.get("basic", {})
        pid = int(basic.get("pid") or 0)

        modules = [m for m in pdata.get("modules", []) if isinstance(m, str)]
        open_files = [f for f in pdata.get("open_files", []) if isinstance(f, str)]
        hidden_windows = pdata.get("hidden_windows", [])

        # user32/gdi presence
        has_user32_gdi = self._has_any(modules, ["user32.dll", "gdi32.dll", "win32u.dll"])
        hidden_window_count = len(hidden_windows) if isinstance(hidden_windows, list) else 0
        has_win32_hooks = bool(has_user32_gdi and hidden_window_count > 0)

        # suspicious log patterns
        suspicious_patterns = [r"\.dat$", r"\.log$", r"\.tmp$"]

        def is_suspicious_log(p: str) -> bool:
            lp = p.lower()
            if self.collector.is_suspicious_path(lp):
                return True
            for pat in suspicious_patterns:
                try:
                    if re.search(pat, lp):
                        return True
                except Exception:
                    pass
            return False

        writes_to_suspicious = any(is_suspicious_log(p) for p in open_files)

        proc = self.collector._safe_process(pid)
        io_stats, net_stats = self._sample_io_and_connections(proc, duration=sample_duration)

        frequent_writes = io_stats["write_count_delta"] >= 3 or io_stats["write_bytes_delta"] >= 4096
        frequent_suspicious_writes = bool(writes_to_suspicious and frequent_writes)

        clipboard_heuristic = bool(has_user32_gdi and frequent_suspicious_writes)

        exfiltration_heuristic = False
        try:
            exfiltration_heuristic = bool(
                net_stats["new_conn_count"] >= 2 and io_stats["write_bytes_delta"] <= 2048
            )
        except Exception:
            pass

        sedebug = self._token_has_sedebug(pid)
        thread_injection_heuristic = bool(sedebug) if sedebug is not None else False

        return {
            "has_user32_gdi": has_user32_gdi,
            "has_win32_hooks": has_win32_hooks,
            "hidden_window_count": hidden_window_count,
            "frequent_suspicious_writes": frequent_suspicious_writes,
            "clipboard_heuristic": clipboard_heuristic,
            "exfiltration_heuristic": exfiltration_heuristic,
            "thread_injection_heuristic": thread_injection_heuristic,
            "io_stats": io_stats,
            "net_stats": {
                "new_conn_count": net_stats.get("new_conn_count", 0),
                "remote_endpoints": list(net_stats.get("remote_endpoints", set())),
            },
        }
# =====================================================================
# ScoringEngine
# =====================================================================

class ScoringEngine:
    """Computes transparent risk scores for potential keylogger behavior."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or LOGGER
        self.weights = {
            "file_path_suspicious": 10,
            "hook_indicators": 20,
            "hidden_window_count": 10,
            "suspicious_dlls": 10,
            "continuous_file_writes": 15,
            "registry_persistence": 10,
            "network_exfiltration": 10,
            "api_call_patterns": 10,
            "thread_injection": 15,
            "no_signature": 10,
            "temp_folder": 10,
            "startup_presence": 10,
        }

    def _in_temp(self, path: str) -> bool:
        """Return True if path resides under the TEMP directory."""
        try:
            tmp = os.environ.get("TEMP") or os.environ.get("TMP") or ""
            return path.lower().startswith(tmp.lower()) if tmp else False
        except Exception:
            return False

    def score(
        self,
        pdata: Dict[str, Any],
        indicators: Dict[str, Any],
        persistence: Dict[str, List[str]],
        scheduled: List[str],
        startup_entries: List[str],
    ) -> Dict[str, Any]:
        """Compute risk score and explanations."""
        basic = pdata.get("basic", {})
        exe = basic.get("exe") or ""
        modules = [m for m in pdata.get("modules", []) if isinstance(m, str)]
        hidden_window_count = indicators.get("hidden_window_count", 0) or 0

        explanations: List[str] = []
        total = 0

        # Suspicious installation path
        if pdata.get("path_suspicious"):
            w = self.weights["file_path_suspicious"]
            total += w
            explanations.append(f"+{w}: Executable in user-writable/hidden location")

        # Hook indicators
        if indicators.get("has_win32_hooks"):
            w = self.weights["hook_indicators"]
            total += w
            explanations.append(f"+{w}: Hidden windows + user32/gdi modules")

        # Hidden windows
        if hidden_window_count > 0:
            add = min(self.weights["hidden_window_count"], hidden_window_count * 2)
            total += add
            explanations.append(f"+{add}: {hidden_window_count} hidden window(s)")

        # DLLs
        if any(os.path.basename(m).lower() in {"user32.dll", "gdi32.dll", "win32u.dll"} for m in modules):
            w = self.weights["suspicious_dlls"]
            total += w
            explanations.append(f"+{w}: Suspicious DLL modules loaded")

        # Continuous write patterns
        if indicators.get("frequent_suspicious_writes"):
            w = self.weights["continuous_file_writes"]
            total += w
            explanations.append(f"+{w}: Frequent writes to suspicious log files")

        # Registry persistence
        reg_hit = False
        reg_cat = None
        for cat in ("Run", "RunOnce", "PoliciesRun", "Services"):
            try:
                for entry in persistence.get(cat, []):
                    if exe and exe.lower() in entry.lower():
                        reg_hit = True
                        reg_cat = cat
                        break
                if reg_hit:
                    break
            except Exception:
                pass
        if reg_hit:
            w = self.weights["registry_persistence"]
            total += w
            explanations.append(f"+{w}: Executable referenced in registry persistence ({reg_cat})")

        # Network exfiltration
        if indicators.get("exfiltration_heuristic"):
            w = self.weights["network_exfiltration"]
            total += w
            explanations.append(f"+{w}: Outbound connection spikes during sampling")

        # API call patterns implied by DLL loads
        if indicators.get("has_user32_gdi"):
            w = self.weights["api_call_patterns"]
            total += w
            explanations.append(f"+{w}: user32/gdi typically used for keyboard hooks")

        # Thread injection
        if indicators.get("thread_injection_heuristic"):
            w = self.weights["thread_injection"]
            total += w
            explanations.append(f"+{w}: SeDebugPrivilege enabled")

        # Signature check
        sig = pdata.get("signature", {})
        signed = sig.get("signed")
        publisher = sig.get("publisher")
        if signed is False or (signed is None and not publisher):
            w = self.weights["no_signature"]
            total += w
            explanations.append(f"+{w}: Unsigned binary or unknown publisher")

        # Temp folder
        if exe and self._in_temp(exe):
            w = self.weights["temp_folder"]
            total += w
            explanations.append(f"+{w}: Executable resides in TEMP directory")

        # Startup presence
        startup_hit = any(exe and exe.lower() in (s.lower()) for s in startup_entries)
        if startup_hit:
            w = self.weights["startup_presence"]
            total += w
            explanations.append(f"+{w}: File present in Startup folder")

        # Clamp risk
        total = max(0, min(100, total))

        severity = "low"
        if total >= 80:
            severity = "critical"
        elif total >= 60:
            severity = "high"
        elif total >= 40:
            severity = "medium"

        return {
            "score": int(total),
            "severity": severity,
            "explanations": explanations,
        }
# =====================================================================
# KeyloggerDetector  (with system-process skip + progress + log callback)
# =====================================================================

class KeyloggerDetector:
    """
    Orchestrates collection, analysis, scoring, and reporting.

    New features added:
      ✔ skip_system_processes (faster scanning)
      ✔ stop_callback() → early cancellation support
      ✔ log_callback(msg: str) → live log per process
      ✔ progress_callback(percent: int) → GUI progress sync
    """

    def __init__(
        self,
        sample_duration: float = 3.0,
        logger: Optional[logging.Logger] = None,
        skip_system_processes: bool = True,
        stop_callback: Optional[Callable[[], bool]] = None,
        log_callback: Optional[Callable[[str], None]] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> None:

        self.logger = logger or LOGGER
        self.collector = ProcessCollector(logger=self.logger)
        self.analyzer = BehaviorAnalyzer(self.collector, logger=self.logger)
        self.scorer = ScoringEngine(logger=self.logger)

        self.sample_duration = sample_duration
        self.skip_system_processes = bool(skip_system_processes)

        self.stop_callback = stop_callback
        self.log_callback = log_callback
        self.progress_callback = progress_callback

        # Persistence sources (cached)
        self.registry_persistence = self.collector.get_registry_persistence()
        self.scheduled_tasks = self.collector.get_scheduled_tasks()
        self.startup_entries = self.collector.get_startup_folder_entries()

    # ------------------------------------------------------------
    # System Process Filter
    # ------------------------------------------------------------
    def _is_system_process(self, basic: Dict[str, Any]) -> bool:
        """
        Skip Windows core processes to speed up scanning.
        """
        try:
            name = (basic.get("name") or "").lower()
            exe = (basic.get("exe") or "").lower()
            user = (basic.get("username") or "").lower()
        except Exception:
            return False

        # Known system processes
        if name in ("system", "idle", "registry"):
            return True

        # Windows service accounts
        if user.startswith("nt authority\\"):
            return True
        if user.startswith("local service") or user.startswith("network service"):
            return True

        # Windows directory executable
        try:
            if exe.startswith(r"c:\\windows\\"):
                return True
        except Exception:
            pass

        return False

    # ------------------------------------------------------------
    # Core detection loop
    # ------------------------------------------------------------
    def detect(self) -> Dict[str, Any]:
        """Run full heuristic scan and return the final report."""

        results: List[Dict[str, Any]] = []
        pids = self.collector.iter_processes()
        total = len(pids) or 1
        processed = 0

        for pid in pids:

            # A) Cooperative cancel
            try:
                if self.stop_callback and self.stop_callback():
                    if self.log_callback:
                        self.log_callback("⛔ Scan cancelled early.")
                    break
            except Exception:
                pass

            basic = self.collector.get_basic_info(pid)

            # B) Skip system processes for speed
            if self.skip_system_processes and self._is_system_process(basic):
                processed += 1
                if self.progress_callback:
                    pct = int(processed / total * 100)
                    self.progress_callback(pct)
                continue

            # C) Log process being scanned
            if self.log_callback:
                name = basic.get("name", "unknown")
                self.log_callback(f"Scanning PID {pid} → {name}")

            # D) Full metadata
            try:
                pdata = self.collector.collect_for_pid(pid)
                pdata["basic"] = basic
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"Failed to collect PID {pid}: {e}")
                processed += 1
                continue

            # E) Behavioral analysis
            indicators = self.analyzer.analyze(pdata, sample_duration=self.sample_duration)

            # F) Risk scoring
            risk = self.scorer.score(
                pdata,
                indicators,
                persistence=self.registry_persistence,
                scheduled=self.scheduled_tasks,
                startup_entries=self.startup_entries,
            )
            pdata["indicators"] = indicators
            pdata["risk"] = risk
            results.append(pdata)

            # G) Update progress
            processed += 1
            try:
                if self.progress_callback:
                    pct = int(processed / total * 100)
                    self.progress_callback(pct)
            except Exception:
                pass

        # High risk subset
        high_risk = [r for r in results if r.get("risk", {}).get("severity") in {"high", "critical"}]

        return {
            "summary": {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "process_count": len(results),
                "high_risk_count": len(high_risk),
            },
            "persistence": self.registry_persistence,
            "scheduled_tasks": self.scheduled_tasks,
            "startup_entries": self.startup_entries,
            "processes": results,
            "high_risk": high_risk,
        }
    # ------------------------------------------------------------
    # Write JSON report
    # ------------------------------------------------------------
    def write_json(self, report: Dict[str, Any], path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            return path
        except Exception as e:
            self.logger.error(f"Failed to write JSON report to {path}: {e}")
            return None

    # ------------------------------------------------------------
    # Write CSV report
    # ------------------------------------------------------------
    def write_csv(self, report: Dict[str, Any], path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "pid", "name", "exe", "severity", "score", "hidden_windows",
                    "has_user32_gdi", "frequent_suspicious_writes", "exfiltration",
                    "signed", "publisher",
                ])
                for p in report.get("processes", []):
                    b = p.get("basic", {})
                    ind = p.get("indicators", {})
                    sig = p.get("signature", {})
                    risk = p.get("risk", {})
                    writer.writerow([
                        b.get("pid"),
                        b.get("name"),
                        b.get("exe"),
                        risk.get("severity"),
                        risk.get("score"),
                        ind.get("hidden_window_count"),
                        ind.get("has_user32_gdi"),
                        ind.get("frequent_suspicious_writes"),
                        ind.get("exfiltration_heuristic"),
                        sig.get("signed"),
                        sig.get("publisher"),
                    ])
            return path
        except Exception as e:
            self.logger.error(f"Failed to write CSV report to {path}: {e}")
            return None

    # ------------------------------------------------------------
    # Print Summary (CLI)
    # ------------------------------------------------------------
    def print_summary(self, report: Dict[str, Any], verbose: bool = False) -> None:
        summary = report.get("summary", {})
        print(
            f"[Summary] {summary.get('timestamp')} | "
            f"Processes: {summary.get('process_count')} | "
            f"High-Risk: {summary.get('high_risk_count')}"
        )
        if not verbose:
            print("High-Risk PIDs:")
            for p in report.get("high_risk", []):
                b = p.get("basic", {})
                risk = p.get("risk", {})
                print(f"  PID {b.get('pid')}: {b.get('name')} | Score {risk.get('score')} ({risk.get('severity')})")
        else:
            print("High-Risk Detailed:")
            for p in report.get("high_risk", []):
                b = p.get("basic", {})
                ind = p.get("indicators", {})
                risk = p.get("risk", {})
                print(f"  PID {b.get('pid')}: {b.get('name')} | Exe: {b.get('exe')}")
                print(f"    Score {risk.get('score')} ({risk.get('severity')})")
                for exp in risk.get("explanations", []):
                    print(f"      - {exp}")
                print(
                    f"    Hidden windows: {ind.get('hidden_window_count')} | "
                    f"user32/gdi: {ind.get('has_user32_gdi')} | "
                    f"Writes: {ind.get('frequent_suspicious_writes')} | "
                    f"Exfil: {ind.get('exfiltration_heuristic')}"
                )


# =====================================================================
# Public API (Used by GUI)
# =====================================================================

def detect_keyloggers(
    sample_duration: float = 3.0,
    skip_system_processes: bool = True,
    log_callback=None,
    progress_callback=None
) -> Dict[str, Any]:

    detector = KeyloggerDetector(
        sample_duration=sample_duration,
        skip_system_processes=skip_system_processes,
        log_callback=log_callback,
        progress_callback=progress_callback,
    )
    return detector.detect()


def kill_process(processes: List[Tuple[str, int]]) -> Dict[int, Tuple[bool, str]]:
    """Terminate processes by PID."""
    results: Dict[int, Tuple[bool, str]] = {}
    for image_name, pid in processes:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            results[pid] = (True, f"Process {image_name} (PID {pid}) terminated")
            log_detection(f"{image_name} (PID {pid})", " Process terminated")
        except Exception as e:
            msg = f"Failed to terminate {image_name} (PID {pid}): {e}"
            results[pid] = (False, msg)
            log_detection(f"{image_name} (PID {pid})", " Failed to terminate process")
    return results


# =====================================================================
# CLI Support
# =====================================================================

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Windows heuristic keylogger detector")
    parser.add_argument("--json", dest="json_path", help="Write JSON report", default=None)
    parser.add_argument("--csv", dest="csv_path", help="Write CSV report", default=None)
    parser.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Print verbose details"
    )
    parser.add_argument(
        "--sample",
        dest="sample_duration",
        type=float,
        default=3.0,
        help="Sampling duration (seconds)"
    )
    parser.add_argument(
        "--no-skip-system",
        dest="no_skip_system",
        action="store_true",
        help="Include Windows system processes (slower)"
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)

    detector = KeyloggerDetector(
        sample_duration=args.sample_duration,
        skip_system_processes=not args.no_skip_system
    )

    report = detector.detect()
    detector.print_summary(report, verbose=args.verbose)

    jp = detector.write_json(report, args.json_path)
    cp = detector.write_csv(report, args.csv_path)

    if jp:
        print(f"Wrote JSON → {jp}")
    if cp:
        print(f"Wrote CSV → {cp}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
