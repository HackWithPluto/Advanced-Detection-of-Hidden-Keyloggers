import subprocess
import os
import io
import json
import time
import tkinter as tk
from tkinter import messagebox
import psutil
import subprocess
from datetime import datetime
# -----------------------------
# Logging functions
# -----------------------------
def log_detection(process, message):
    print(f"[DETECTION] {process} - {message}")

def log_kill_process(image_name, pid, success=True):
    status = "SUCCESS" if success else "FAILED"
    print(f"[KILL] {image_name} (PID {pid}) - {status}")

# -----------------------------
# Get running processes (Windows)
# -----------------------------
def get_process_list():
    if os.name != "nt":
        raise RuntimeError("System scanning is only implemented for Windows.")

    try:
        raw = subprocess.check_output("tasklist /FO LIST", shell=True, stderr=subprocess.STDOUT)
        text = raw.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to run tasklist: {e}")

    processes = []
    buf = {}
    for line in io.StringIO(text):
        line = line.rstrip("\r\n")
        if not line.strip():
            if "Image Name" in buf and "PID" in buf:
                processes.append((buf["Image Name"].strip(), buf["PID"].strip()))
            buf = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            buf[k.strip()] = v.strip()
    if "Image Name" in buf and "PID" in buf:
        processes.append((buf["Image Name"].strip(), buf["PID"].strip()))
    return processes

# -----------------------------
# Load IOC patterns
# -----------------------------
def load_iocs(path="ioc.json"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            cleaned = []
            for item in data:
                if isinstance(item, dict) and "name" in item:
                    cleaned.append(item["name"])
                elif isinstance(item, str):
                    cleaned.append(item)
            return cleaned
    except FileNotFoundError:
        print(f"[!] IOC file '{path}' not found.")
        return []
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse '{path}': {e}")
        return []

# -----------------------------
# Check running processes
# -----------------------------
def check_processes(ioc_path="ioc.json"):
    processes = get_process_list()
    ioc_names = load_iocs(ioc_path)
    if not ioc_names:
        return []

    detected = []
    ioc_lower = [s.lower() for s in ioc_names]
    for image, pid in processes:
        if any(ioc in image.lower() for ioc in ioc_lower):
            detected.append((image, pid))
            log_detection(f"Process: {image} (PID {pid})", "Suspicious process detected")
    return detected


LOG_FILE = os.path.join("database", "logs", "scan_logs.txt")

def write_log(message):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")
# -----------------------------
# Kill all suspicious processes with GUI confirmation
# -----------------------------
def kill_process(processes):
    results = {}
    for image, pid in processes:
        killed_pids = []
        failed_pids = []

        try:
            # Kill ALL processes with the same executable name
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info["name"] == image:
                    try:
                        proc.kill()  # Force kill
                        proc.wait(timeout=2)
                        killed_pids.append(proc.pid)
                    except Exception:
                        try:
                            subprocess.run(["taskkill", "/PID", str(proc.pid), "/F"], capture_output=True)
                            killed_pids.append(proc.pid)
                        except Exception as e2:
                            failed_pids.append((proc.pid, str(e2)))

            # Prepare summarized log message
            if killed_pids:
                for proc_id in killed_pids:
                    write_log(f"[KILL] SUCCESS → {image} ")
                msg = f"Terminated all processes of {image} (PIDs: {', '.join(map(str, killed_pids))})"
                results[image] = (True, msg)

            if failed_pids:
                for proc_id, err in failed_pids:
                    write_log(f"[KILL] FAILED → {image} reason: {err}")
                details = "; ".join([f"{pid}: {err}" for pid, err in failed_pids])
                msg = f"Failed to kill {image} processes → {details}"
                results[image] = (False, msg)

            if not killed_pids and not failed_pids:
                msg = f"[KILL] No running instances of {image} found."
                write_log(msg)
                results[image] = (False, msg)


        except Exception as e:
            msg = f"Error handling {image} (PID {pid}): {e}"
            write_log(msg)
            results[image] = (False, msg)

    return results

# -----------------------------
# Scan -> Kill -> Confirm with GUI
# -----------------------------
def scan_kill_confirm_gui(ioc_path="ioc.json"):
    detected = check_processes(ioc_path)

    if not detected:
        messagebox.showinfo("Scan Result", "No suspicious processes found.")
        return

    msg = f"Found {len(detected)} suspicious process(es):\n"
    for image, pid in detected:
        msg += f"    -> {image} (PID {pid})\n"
    msg += "\nDo you want to terminate ALL of them?"
    answer = messagebox.askyesno("Terminate All Processes", msg)
    if answer:
        kill_process(detected)
    else:
        messagebox.showinfo("Confirmation", "No processes were terminated.")

    # Short delay
    time.sleep(1)

    still_running = check_processes(ioc_path)
    if still_running:
        msg = "Some suspicious processes are still running:\n"
        for image, pid in still_running:
            msg += f"    -> {image} (PID {pid})\n"
        messagebox.showerror("Confirmation", msg)
    else:
        messagebox.showinfo("Confirmation", "All suspicious processes terminated successfully.")

