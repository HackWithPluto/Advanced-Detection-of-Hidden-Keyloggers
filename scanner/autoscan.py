# autoscan.py
import os
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from scanner.file_scanner import scan_file, SUPPORTED
from utils.logger import log_detection, log_scan_start, log_scan_end

# -------- helpers --------
def _normalize_supported(supported):
    """
    Return a set of normalized extensions (leading dot, lowercase).
    Works whether SUPPORTED contains 'exe' or '.exe'.
    """
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
        window_secs = int(days) * 24 * 60 * 60
        # prefer mtime, keep ctime as fallback
        return (now - st.st_mtime) <= window_secs or (now - st.st_ctime) <= window_secs
    except Exception:
        return False

def _expand_scan_folders(folders):
    """
    Ensure each configured folder entry is converted into an absolute path.
    Accepts absolute paths, relative paths, ~ and env vars. Skips non-existent dirs.
    Returns list of existing absolute directories (duplicates removed, order preserved).
    """
    if not folders:
        return []

    expanded = []
    seen = set()

    for entry in folders:
        if not entry:
            continue

        # expand env vars and user (~)
        try:
            cand = os.path.expandvars(os.path.expanduser(str(entry)))
        except Exception:
            cand = str(entry)

        # if relative -> make absolute relative to current working directory
        if not os.path.isabs(cand):
            cand = os.path.abspath(cand)

        # canonicalize path
        cand = os.path.normpath(cand)

        # only include if directory exists
        if os.path.isdir(cand):
            if cand not in seen:
                seen.add(cand)
                expanded.append(cand)
        else:
            # warn to console or rely on logger; avoid raising
            try:
                # utils.logger may not have 'logger'; using print as lightweight fallback
                print(f"[autoscan] WARNING: configured folder does not exist or is not a directory -> {cand}")
            except Exception:
                pass

    return expanded

def collect_files_for_window(folders, days):
    """
    Walk given folders and return list of files with extensions in SUPPORTED
    and that are within the time window.
    """
    collected = []
    seen = set()
    supported_norm = _normalize_supported(SUPPORTED)

    # Expand and filter folders (absolute existing dirs only)
    folders_expanded = _expand_scan_folders(folders)

    for folder in folders_expanded:
        try:
            for root_dir, _, files in os.walk(folder):
                for f in files:
                    fp = os.path.join(root_dir, f)
                    try:
                        ext = os.path.splitext(fp)[1].lower()
                    except Exception:
                        ext = ''
                    if ext in supported_norm and _within_window(fp, days):
                        if fp not in seen:
                            seen.add(fp)
                            collected.append(fp)
        except Exception as e:
            # log but continue
            try:
                print(f"[autoscan] WARNING: failed to walk folder {folder}: {e}")
            except Exception:
                pass

    return collected

# -------- main scan function --------
def run_autoscan_scan(folders, days, per_file_timeout, callbacks, stop_event):
    """
    folders: list from config (can be absolute paths)
    days: integer window
    per_file_timeout: seconds for each file scan
    callbacks: dict with 'append_result_safe', 'update_progress_safe', 'complete_callback', 'log_callback', 'result_box', 'progress_bar'
    stop_event: threading.Event-like object
    """
    files = collect_files_for_window(folders, days)
    total = max(1, len(files))

    append_result_safe = callbacks.get("append_result_safe")
    update_progress_safe = callbacks.get("update_progress_safe")
    complete_callback = callbacks.get("complete_callback")
    log_callback = callbacks.get("log_callback")

    log_scan_start("Auto Scan")

    with ThreadPoolExecutor(max_workers=1) as executor:
        for idx, fp in enumerate(files, start=1):
            # allow stop_event to cancel
            if hasattr(stop_event, "is_set") and stop_event.is_set():
                if append_result_safe:
                    try:
                        append_result_safe(callbacks.get("result_box"), "--- Scan cancelled ---")
                    except Exception:
                        pass
                break

            future = executor.submit(scan_file, fp, True)
            try:
                result = future.result(timeout=per_file_timeout)
                # result may be None or not dict; handle safely
                if isinstance(result, dict):
                    status = result.get("status", "UNKNOWN")
                else:
                    status = str(result)

                if log_callback:
                    try:
                        log_callback(fp, status)
                    except Exception:
                        pass

                if update_progress_safe:
                    try:
                        progress_value = int((idx / total) * 100)
                    except Exception:
                        progress_value = 0
                    try:
                        update_progress_safe(callbacks.get("progress_bar"), progress_value)
                    except Exception:
                        pass

            except TimeoutError:
                log_detection(fp, "Error: per-file timeout")
                if append_result_safe:
                    try:
                        append_result_safe(callbacks.get("result_box"), f"{fp} → ERROR: Timeout")
                    except Exception:
                        pass
            except Exception as e:
                log_detection(fp, f"Error: {e}")
                if append_result_safe:
                    try:
                        append_result_safe(callbacks.get("result_box"), f"{fp} → ERROR: {e}")
                    except Exception:
                        pass

    # finish progress
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
