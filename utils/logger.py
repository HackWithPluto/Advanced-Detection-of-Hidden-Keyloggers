import os
from datetime import datetime

# Log file path (inside database/logs/)
LOG_DIR = os.path.join("database", "logs")
LOG_FILE = os.path.join(LOG_DIR, "scan_logs.txt")

# Ensure the log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

def log_detection(item, result, log_file=LOG_FILE):
    """
    Log a detection or action to the log file.
    item: file name, process name, or action description
    result: description of result (e.g., " Suspicious", " Clean")
    """
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} → {item} → {result}\n")
    except Exception as e:
        print(f"Logging failed: {e}")

def log_quarantine(file_path, dest_path):
    """
    Log when a file is moved to quarantine.
    """
    log_detection(file_path, f" Quarantined → {dest_path}")

def log_kill_process(image_name, pid, success=True):
    """
    Log when a process is killed or failed.
    """
    result = " Process terminated" if success else " Failed to terminate process"
    log_detection(f"{image_name} (PID {pid})", result)

def log_scan_start(scan_type="File/Folder"):
    """
    Optional: Log start of scan.
    """
    log_detection(f"--- Starting {scan_type} Scan ---", "")

def log_scan_end(scan_type="File/Folder"):
    """
    Optional: Log end of scan.
    """
    log_detection(f"--- Finished {scan_type} Scan ---", "")
