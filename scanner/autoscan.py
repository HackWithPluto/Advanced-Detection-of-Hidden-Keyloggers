#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
scanner/autoscan.py

AutoScan engine with **in-memory logging only**.

- Scans recently created/modified files in configured folders.
- Uses scanner.file_scanner.scan_file for the actual detection logic.
- Stores all autoscan logs in a RAM buffer (no log file is written).
- Exposes helpers so the GUI (e.g. AutoScan Result window) can fetch logs:

    - clear_autoscan_log()
    - append_autoscan_log(entry: dict)
    - get_autoscan_log_snapshot() -> list[dict]

Each log entry is a dict like:
    {
        "type": "file" | "message",
        "time": "YYYY-MM-DDTHH:MM:SS",
        "file": "<path>",          # for type == "file"
        "status": "<status>",      # for type == "file"
        "level": "info|warning|error",  # for type == "message"
        "text": "<message>",       # for type == "message"
    }

This module is **diskless**: no autoscan log file is created.
"""

import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import RLock
from typing import Any, Dict, List

from scanner.file_scanner import scan_file, SUPPORTED

# optional logger
try:
    from utils.logger import log_detection, log_scan_start, log_scan_end
except Exception:
    def log_detection(*a, **k):  # type: ignore[no-redef]
        pass

    def log_scan_start(*a, **k):  # type: ignore[no-redef]
        pass

    def log_scan_end(*a, **k):  # type: ignore[no-redef]
        pass


# ====================================================================================
# In-memory AutoScan log buffer
# ====================================================================================

_AUTOSCAN_LOG_LOCK = RLock()
_AUTOSCAN_LOG_BUFFER: List[Dict[str, Any]] = []


def clear_autoscan_log() -> None:
    """Clear the in-memory autoscan log buffer."""
    with _AUTOSCAN_LOG_LOCK:
        _AUTOSCAN_LOG_BUFFER.clear()


def append_autoscan_log(entry: Dict[str, Any]) -> None:
    """Append a structured log entry to the in-memory buffer."""
    if not isinstance(entry, dict):
        return
    with _AUTOSCAN_LOG_LOCK:
        _AUTOSCAN_LOG_BUFFER.append(entry)


def get_autoscan_log_snapshot() -> List[Dict[str, Any]]:
    """
    Return a shallow copy of the current autoscan log buffer.

    Safe to call from GUI code (e.g. AutoScan Result dialog) to render logs.
    """
    with _AUTOSCAN_LOG_LOCK:
        return list(_AUTOSCAN_LOG_BUFFER)


def _now_str() -> str:
    return datetime.now().isoformat(timespec="seconds")


def log_message(text: str, level: str = "info") -> None:
    """Convenience: append a 'message' entry to the buffer."""
    append_autoscan_log(
        {
            "type": "message",
            "time": _now_str(),
            "level": str(level or "info").lower(),
            "text": str(text),
        }
    )


def log_file_status(file_path: str, status: str) -> None:
    """Convenience: append a 'file' entry to the buffer."""
    append_autoscan_log(
        {
            "type": "file",
            "time": _now_str(),
            "file": str(file_path),
            "status": str(status),
        }
    )


# ====================================================================================
# Helpers
# ====================================================================================

def _normalize_supported(supported):
    out = set()
    for s in (supported or []):
        try:
            ss = str(s).strip().lower()
        except Exception:
            continue
        if not ss:
            continue
        if not ss.startswith('.'):
            ss = '.' + ss
        out.add(ss)
    return out


def _within_window(file_path, days):
    """Return True if file was modified/created within `days` days."""
    try:
        st = os.stat(file_path)
        now = time.time()
        window_secs = int(days) * 86400
        return (now - st.st_mtime) <= window_secs or (now - st.st_ctime) <= window_secs
    except Exception:
        return False


def _expand_scan_folders(folders):
    """
    Normalize and validate folder list.

    Returns only existing absolute directories.
    Logs warnings to the in-memory autoscan buffer for missing folders.
    """
    if not folders:
        return []

    expanded = []
    seen = set()

    for entry in folders:
        if not entry:
            continue

        try:
            cand = os.path.expandvars(os.path.expanduser(str(entry)))
        except Exception:
            cand = str(entry)

        if not os.path.isabs(cand):
            cand = os.path.abspath(cand)

        cand = os.path.normpath(cand)

        if os.path.isdir(cand):
            if cand not in seen:
                seen.add(cand)
                expanded.append(cand)
        else:
            msg = f"[autoscan] WARNING: folder not found → {cand}"
            print(msg)
            log_message(msg, level="warning")

    return expanded


def collect_files_for_window(folders, days):
    """
    Collect candidate files to scan from the given folders, restricted to the
    scan window (last `days` days) and supported extensions.
    """
    collected = []
    seen = set()
    supported_norm = _normalize_supported(SUPPORTED)

    folders_expanded = _expand_scan_folders(folders)

    for folder in folders_expanded:
        try:
            for root_dir, _, files in os.walk(folder):
                for f in files:
                    fp = os.path.join(root_dir, f)
                    ext = os.path.splitext(fp)[1].lower()

                    if ext in supported_norm and _within_window(fp, days):
                        if fp not in seen:
                            seen.add(fp)
                            collected.append(fp)
        except Exception as e:
            msg = f"[autoscan] WARNING: cannot walk {folder}: {e}"
            print(msg)
            log_message(msg, level="warning")

    return collected


# ====================================================================================
# MAIN AUTOSCAN SCAN FUNCTION
# ====================================================================================

def run_autoscan_scan(folders, days, per_file_timeout, callbacks, stop_event):
    """
    Main autoscan engine using **in-memory log capture only**.

    Arguments:
        folders            : list of folder paths to scan
        days               : scan window (integer days)
        per_file_timeout   : per-file timeout in seconds
        callbacks          : dict with optional keys:
                             - "append_result_safe"(result_box, msg)   [unused here]
                             - "update_progress_safe"(progress_bar, v)
                             - "complete_callback"()
                             - "log_callback"(file_path, status)
        stop_event         : threading.Event checked to allow cancel.

    This function:
        - clears the in-memory autoscan log buffer at start
        - appends structured log entries for messages and each file scanned
        - does NOT create or write any log file on disk
    """
    # Reset previous in-memory logs
    clear_autoscan_log()

    log_message("===== AutoScan Started =====", level="info")
    log_message(f"Time: {datetime.now()}", level="info")
    log_scan_start("Auto Scan")

    files = collect_files_for_window(folders, days)
    total = max(1, len(files))

    append_result_safe = callbacks.get("append_result_safe")
    update_progress_safe = callbacks.get("update_progress_safe")
    complete_callback = callbacks.get("complete_callback")
    log_callback = callbacks.get("log_callback")

    with ThreadPoolExecutor(max_workers=1) as executor:
        for idx, fp in enumerate(files, start=1):

            if hasattr(stop_event, "is_set") and stop_event.is_set():
                log_message("--- Scan cancelled by user ---", level="info")
                break

            future = executor.submit(scan_file, fp, True)

            try:
                result = future.result(timeout=per_file_timeout)

                if isinstance(result, dict):
                    status = result.get("status", "UNKNOWN")
                else:
                    status = str(result)

                # in-memory log for this file
                log_file_status(fp, status)

                if log_callback:
                    log_callback(fp, status)

                if update_progress_safe:
                    try:
                        update_progress_safe(
                            callbacks.get("progress_bar"),
                            int((idx / total) * 100),
                        )
                    except Exception:
                        pass

            except TimeoutError:
                log_detection(fp, "Timeout")
                msg = f"{fp} → ERROR: Timeout"
                log_message(msg, level="error")
                log_file_status(fp, "timeout")

                if append_result_safe:
                    try:
                        append_result_safe(callbacks.get("result_box"), msg)
                    except Exception:
                        pass

            except Exception as e:
                log_detection(fp, str(e))
                msg = f"{fp} → ERROR: {e}"
                log_message(msg, level="error")
                log_file_status(fp, "error")

                if append_result_safe:
                    try:
                        append_result_safe(callbacks.get("result_box"), msg)
                    except Exception:
                        pass

    # finish
    log_message("===== AutoScan Done =====", level="info")
    log_message("", level="info")

    if update_progress_safe:
        try:
            update_progress_safe(callbacks.get("progress_bar"), 100)
        except Exception:
            pass

    if complete_callback:
        try:
            complete_callback()
        except Exception:
            pass

    log_scan_end("Auto Scan")
