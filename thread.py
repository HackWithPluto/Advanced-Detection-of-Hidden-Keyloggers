import threading
import os
import time
from scanner.file_scanner import scan_file, scan_folder
from utils.analyzer import analyze_file
from utils.quarantine import quarantine_file
from scanner.system_scanner import check_processes, kill_process

# Stop event to cancel scanning
stop_event = threading.Event()


# -----------------------------
# Thread-safe GUI updates
# -----------------------------
def append_result_safe(result_box, text, tag=None):
    """Thread-safe text insertion into a GUI Text widget"""
    if result_box:
        def insert_text():
            result_box.configure(state="normal")
            if tag:
                result_box.insert("end", text + "\n", tag)
            else:
                result_box.insert("end", text + "\n")
            result_box.see("end")
            result_box.configure(state="disabled")
        result_box.after(0, insert_text)


def update_progress_safe(progress_bar, value):
    """Thread-safe progress bar update (value: 0-100)"""
    if progress_bar:
        progress_bar.after(0, lambda: progress_bar.set(value / 100))


# -----------------------------
# Scan single/multiple files
# -----------------------------
def scan_files_thread(result_box, file_paths, progress_bar=None, callback=None, on_complete=None):
    if not isinstance(file_paths, (list, tuple)):
        file_paths = [file_paths]

    logged_files = set()  # Track already logged files to prevent duplicates

    def worker():
        total_files = len(file_paths)
        for idx, file_path in enumerate(file_paths, start=1):
            if stop_event.is_set():
                append_result_safe(result_box, "--- Scan cancelled ---")
                break

            # Smooth progress simulation
            steps = 20
            for step in range(steps):
                if stop_event.is_set():
                    break
                if progress_bar:
                    progress_value = ((idx - 1) + (step + 1) / steps) / total_files * 100
                    update_progress_safe(progress_bar, progress_value)
                time.sleep(0.01)

            try:
                ext = os.path.splitext(file_path)[1].lower()
                if ext in [".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tar.bz2"]:
                    archive_results = scan_file(file_path, quarantine_prompt=True)
                    for r in archive_results:
                        f = r['file']
                        if f in logged_files:
                            continue
                        logged_files.add(f)

                        status = r["status"]
                        if callback:
                            callback(f, status)
                        if status == "suspicious" and r["action"] == "prompt":
                            quarantine_file(f, parent=result_box.master, ask_user=True)
                else:
                    result = analyze_file(file_path, parent=result_box.master, ask_quarantine=True)
                    f = file_path
                    if f not in logged_files:
                        logged_files.add(f)

                        status = result["status"]
                        if callback:
                            callback(f, status)
                        if status == "suspicious" and result["action"] == "quarantined":
                            quarantine_file(f, parent=result_box.master, ask_user=False)

            except Exception as e:
                if file_path not in logged_files:
                    logged_files.add(file_path)
                    append_result_safe(result_box, f"{file_path} → ERROR: {e}")

            # Final progress for this file
            if progress_bar:
                progress_value = (idx / total_files) * 100
                update_progress_safe(progress_bar, progress_value)

        if on_complete:
            on_complete()

    threading.Thread(target=worker, daemon=True).start()


# -----------------------------
# Scan folder recursively
# -----------------------------
def scan_folder_thread(result_box, folder_path, progress_bar=None, recursive=True, callback=None, on_complete=None):
    logged_files = set()  # Prevent duplicate logs

    def worker():
        append_result_safe(result_box, f"--- Scanning folder: {folder_path} ---", tag="folder")
        try:
            all_results = scan_folder(folder_path, recursive=recursive, quarantine_prompt=True)
            if isinstance(all_results, dict):
                all_results = [all_results]

            total_files = len(all_results) if all_results else 1

            def handle_result(r):
                f = r.get("file", "Unknown")
                if f in logged_files:
                    return
                logged_files.add(f)

                status = r.get("status")
                if callback:
                    callback(f, status)
                if status == "suspicious" and r.get("action") == "prompt":
                    quarantine_file(f, parent=result_box.master, ask_user=True)

            for idx, result in enumerate(all_results, start=1):
                if stop_event.is_set():
                    append_result_safe(result_box, "--- Scan cancelled ---")
                    break

                # Flatten archives
                if isinstance(result, list):
                    for sub_result in result:
                        if isinstance(sub_result, dict):
                            handle_result(sub_result)
                elif isinstance(result, dict):
                    handle_result(result)

                # Smooth live progress
                steps = 10
                for step in range(steps):
                    if stop_event.is_set():
                        break
                    if progress_bar:
                        progress_value = ((idx - 1) + (step + 1) / steps) / total_files * 100
                        update_progress_safe(progress_bar, progress_value)
                    time.sleep(0.005)

            # Final progress
            if progress_bar:
                update_progress_safe(progress_bar, 100)

        except Exception as e:
            append_result_safe(result_box, f"Folder scan error: {e}")

        if on_complete:
            on_complete()

    threading.Thread(target=worker, daemon=True).start()


# -----------------------------
# Scan system processes
# -----------------------------
def scan_system_processes_thread(result_box, progress_bar=None, callback=None, on_complete=None):
    logged_processes = set()  # Prevent duplicate logs

    def worker():
        append_result_safe(result_box, "--- Scanning system processes ---")
        try:
            detected = check_processes("ioc.json")
            if not detected:
                append_result_safe(result_box, " No suspicious processes detected.\n")
                if on_complete:
                    on_complete()
                return

            total_detected = len(detected)
            for idx, (image, pid) in enumerate(detected, start=1):
                if stop_event.is_set():
                    append_result_safe(result_box, "--- Scan cancelled ---")
                    break

                if image in logged_processes:
                    continue
                logged_processes.add(image)

                if callback:
                    callback(image, "suspicious")

                if result_box.master:
                    from tkinter import messagebox
                    if messagebox.askyesno("Kill Process",
                                           f"Do you want to terminate {image} (PID {pid})?",
                                           parent=result_box.master):
                        success, output = kill_process(pid, image)
                        append_result_safe(result_box, output.strip())

                # Smooth live progress
                steps = 10
                for step in range(steps):
                    if stop_event.is_set():
                        break
                    if progress_bar and total_detected > 0:
                        progress_value = ((idx - 1) + (step + 1) / steps) / total_detected * 100
                        update_progress_safe(progress_bar, progress_value)
                    time.sleep(0.005)

            if progress_bar:
                update_progress_safe(progress_bar, 100)

        except Exception as e:
            append_result_safe(result_box, f"System scan error: {e}")

        if on_complete:
            on_complete()

    threading.Thread(target=worker, daemon=True).start()
