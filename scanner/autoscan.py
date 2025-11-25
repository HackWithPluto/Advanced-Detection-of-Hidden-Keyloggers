import os
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from scanner.file_scanner import scan_file, SUPPORTED
from utils.logger import log_detection, log_scan_start, log_scan_end

def _within_window(file_path, days):
    try:
        st = os.stat(file_path)
        now = time.time()
        window_secs = days * 24 * 60 * 60
        return (now - st.st_ctime) <= window_secs or (now - st.st_mtime) <= window_secs
    except Exception:
        return False

def collect_files_for_window(folders, days):
    collected = []
    seen = set()
    for folder in folders or []:
        if not folder or not os.path.isdir(folder):
            continue
        for root_dir, _, files in os.walk(folder):
            for f in files:
                fp = os.path.join(root_dir, f)
                ext = os.path.splitext(fp)[1].lower()
                if ext in SUPPORTED and _within_window(fp, days):
                    if fp not in seen:
                        seen.add(fp)
                        collected.append(fp)
    return collected

def run_autoscan_scan(folders, days, per_file_timeout, callbacks, stop_event):
    files = collect_files_for_window(folders, days)
    total = max(1, len(files))
    results = []

    append_result_safe = callbacks.get("append_result_safe")
    update_progress_safe = callbacks.get("update_progress_safe")
    complete_callback = callbacks.get("complete_callback")
    log_callback = callbacks.get("log_callback")

    log_scan_start("Auto Scan")

    with ThreadPoolExecutor(max_workers=1) as executor:
        for idx, fp in enumerate(files, start=1):
            if stop_event.is_set():
                if append_result_safe:
                    append_result_safe(callbacks.get("result_box"), "--- Scan cancelled ---")
                break

            future = executor.submit(scan_file, fp, True)
            try:
                result = future.result(timeout=per_file_timeout)
                status = result.get("status")
                if isinstance(result, dict):
                    results.append(result)
                if log_callback:
                    log_callback(fp, status)
                if update_progress_safe:
                    progress_value = (idx / total) * 100
                    update_progress_safe(callbacks.get("progress_bar"), progress_value)
            except TimeoutError:
                log_detection(fp, "Error: per-file timeout")
                if append_result_safe:
                    append_result_safe(callbacks.get("result_box"), f"{fp} → ERROR: Timeout")
                results.append({"file": fp, "status": "error", "action": "none", "verdict": "Timeout", "matches": []})
            except Exception as e:
                log_detection(fp, f"Error: {e}")
                if append_result_safe:
                    append_result_safe(callbacks.get("result_box"), f"{fp} → ERROR: {e}")
                results.append({"file": fp, "status": "error", "action": "none", "verdict": f"Error: {e}", "matches": []})

    if update_progress_safe:
        update_progress_safe(callbacks.get("progress_bar"), 100)

    if complete_callback:
        complete_callback()

    log_scan_end("Auto Scan")
    return results

