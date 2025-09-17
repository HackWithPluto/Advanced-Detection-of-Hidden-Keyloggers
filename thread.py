import threading
import os
from scanner.file_scanner import scan_file, scan_folder
from scanner.file_readers import archive_reader
from utils.analyzer import analyze_file
from utils.quarantine import quarantine_file
from scanner.system_scanner import check_processes, kill_process

# Stop event to cancel scanning
stop_event = threading.Event()

# -----------------------------
# Thread-safe GUI updates
# -----------------------------
def append_result_safe(result_box, text):
    """Thread-safe text insertion into a GUI Text widget"""
    if result_box:
        result_box.after(0, lambda: (
            result_box.configure(state="normal"),
            result_box.insert("end", text + "\n"),
            result_box.see("end"),
            result_box.configure(state="disabled")
        ))

def update_progress_safe(progress_bar, value):
    """Thread-safe progress bar update (value: 0-100)"""
    if progress_bar:
        progress_bar.after(0, lambda: progress_bar.set(value / 100))


# -----------------------------
# Scan single/multiple files
# -----------------------------
def scan_files_thread(result_box, file_paths, progress_bar=None):
    if not isinstance(file_paths, (list, tuple)):
        file_paths = [file_paths]

    def worker():
        total_files = len(file_paths)
        for idx, file_path in enumerate(file_paths, start=1):
            if stop_event.is_set():
                append_result_safe(result_box, "--- Scan cancelled ---")
                break

            try:
                ext = os.path.splitext(file_path)[1].lower()
                if ext in [".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tar.bz2"]:
                    # Scan the archive using scan_file, which internally calls archive_reader
                    archive_results = scan_file(file_path, quarantine_prompt=True)
                    # archive_results is a list of dicts for each extracted file
                    for r in archive_results:
                        status_text = "KEYLOGGER DETECTED" if r["status"] == "suspicious" else "CLEAN FILE"
                        append_result_safe(result_box, f"{r['file']} → {status_text}")
                        if r["status"] == "suspicious" and r["action"] == "prompt":
                            quarantine_file(r["file"], parent=result_box.master, ask_user=True)

                else:
                    # Single file scan
                    result = analyze_file(file_path, parent=result_box.master, ask_quarantine=True)
                    status_text = "KEYLOGGER DETECTED" if result["status"] == "suspicious" else "CLEAN FILE"
                    append_result_safe(result_box, f"{file_path} → {status_text}")
                    if result["status"] == "suspicious" and result["action"] == "quarantined":
                        quarantine_file(file_path, parent=result_box.master, ask_user=False)

            except Exception as e:
                append_result_safe(result_box, f"{file_path} → ERROR: {e}")

            if progress_bar:
                progress_value = int((idx / total_files) * 100)
                update_progress_safe(progress_bar, progress_value)

        append_result_safe(result_box, "--- File scan completed ---\n")
        if progress_bar:
            update_progress_safe(progress_bar, 100)

    threading.Thread(target=worker, daemon=True).start()


# -----------------------------
# Scan folder recursively
# -----------------------------
# -----------------------------
# Scan folder recursively
# -----------------------------
def scan_folder_thread(result_box, folder_path, progress_bar=None, recursive=True):
    def worker():
        append_result_safe(result_box, f"--- Scanning folder: {folder_path} ---")
        try:
            all_results = scan_folder(folder_path, recursive=recursive, quarantine_prompt=True)

            # Normalize return
            if isinstance(all_results, dict):
                all_results = [all_results]

            total_files = len(all_results) if all_results else 0

            def handle_result(r):
                """Process one result dict safely"""
                file_path = r.get("file", "Unknown")
                status_text = "KEYLOGGER DETECTED" if r.get("status") == "suspicious" else "CLEAN FILE"
                append_result_safe(result_box, f"{file_path} → {status_text}")

                if r.get("status") == "suspicious" and r.get("action") == "prompt":
                    quarantine_file(file_path, parent=result_box.master, ask_user=True)

            for idx, result in enumerate(all_results, start=1):
                if stop_event.is_set():
                    append_result_safe(result_box, "--- Scan cancelled ---")
                    break

                # ✅ Handle archives returning nested results
                if isinstance(result, list):
                    for sub_result in result:
                        if isinstance(sub_result, dict):
                            handle_result(sub_result)
                elif isinstance(result, dict):
                    handle_result(result)

                if progress_bar and total_files > 0:
                    progress_value = int((idx / total_files) * 100)
                    update_progress_safe(progress_bar, progress_value)

        except Exception as e:
            append_result_safe(result_box, f"Folder scan error: {e}")

        append_result_safe(result_box, "--- Folder scan completed ---\n")
        if progress_bar:
            update_progress_safe(progress_bar, 100)

    threading.Thread(target=worker, daemon=True).start()


# -----------------------------
# Scan system processes
# -----------------------------
def scan_system_processes_thread(result_box, progress_bar=None):
    def worker():
        append_result_safe(result_box, "--- Scanning system processes ---")
        try:
            detected = check_processes("ioc.json")
            total_detected = len(detected) if detected else 0

            if not detected:
                append_result_safe(result_box, " No suspicious processes detected.\n")
                if progress_bar:
                    update_progress_safe(progress_bar, 100)
                return

            for idx, (image, pid) in enumerate(detected, start=1):
                if stop_event.is_set():
                    append_result_safe(result_box, "--- Scan cancelled ---")
                    break

                append_result_safe(result_box, f" Suspicious process: {image} (PID {pid})")
                if result_box.master:
                    from tkinter import messagebox
                    if messagebox.askyesno("Kill Process",
                                           f"Do you want to terminate {image} (PID {pid})?",
                                           parent=result_box.master):
                        success, output = kill_process(pid, image)
                        append_result_safe(result_box, output.strip())

                if progress_bar and total_detected > 0:
                    progress_value = int((idx / total_detected) * 100)
                    update_progress_safe(progress_bar, progress_value)

        except Exception as e:
            append_result_safe(result_box, f"System scan error: {e}")

        append_result_safe(result_box, "--- System process scan completed ---")
        if progress_bar:
            update_progress_safe(progress_bar, 100)

    threading.Thread(target=worker, daemon=True).start()
