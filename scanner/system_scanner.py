import subprocess
import os
import io
import json
from utils.logger import log_detection, log_kill_process

# -----------------------------
# Get running processes (Windows)
# -----------------------------
def get_process_list():
    """
    Returns a list of tuples: (image_name, pid)
    Uses 'tasklist' command on Windows.
    """
    if os.name != "nt":
        raise RuntimeError("System scanning is only implemented for Windows.")

    try:
        raw = subprocess.check_output("tasklist /FO LIST", shell=True, stderr=subprocess.STDOUT)
        text = raw.decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to run tasklist: {e}")

    processes = []
    buf = {}
    for line in io.StringIO(text):
        line = line.rstrip("\r\n")
        if not line.strip():
            if 'Image Name' in buf and 'PID' in buf:
                processes.append((buf['Image Name'].strip(), buf['PID'].strip()))
            buf = {}
            continue
        if ':' in line:
            k, v = line.split(':', 1)
            buf[k.strip()] = v.strip()
    if 'Image Name' in buf and 'PID' in buf:
        processes.append((buf['Image Name'].strip(), buf['PID'].strip()))
    return processes

# -----------------------------
# Load IOC patterns
# -----------------------------
def load_iocs(path="ioc.json"):
    """
    Load known suspicious process names from JSON.
    Example JSON: ["keylogger.exe", "malware.exe"]
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            cleaned = []
            for item in data:
                if isinstance(item, dict) and 'name' in item:
                    cleaned.append(item['name'])
                elif isinstance(item, str):
                    cleaned.append(item)
            return cleaned
    except FileNotFoundError:
        print(f"IOC file '{path}' not found.")
        return []
    except json.JSONDecodeError as e:
        print(f"Failed to parse '{path}': {e}")
        return []

# -----------------------------
# Check running processes
# -----------------------------
def check_processes(ioc_path="ioc.json"):
    """
    Returns list of suspicious processes detected based on IOC names.
    Each item: (image_name, pid)
    """
    processes = get_process_list()
    ioc_names = load_iocs(ioc_path)
    if not ioc_names:
        return []

    detected = []
    ioc_lower = [s.lower() for s in ioc_names]
    for image, pid in processes:
        if any(ioc in image.lower() for ioc in ioc_lower):
            detected.append((image, pid))
            log_detection(f"Process: {image} (PID {pid})", " Suspicious process detected")
    return detected

# -----------------------------
# Kill suspicious process
# -----------------------------
def kill_process(pid, image_name):
    """
    Force terminate a process by PID.
    Returns True if killed successfully.
    """
    cmd = f"taskkill /F /PID {pid}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        log_kill_process(image_name, pid, success=True)
        return True, out.decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        log_kill_process(image_name, pid, success=False)
        return False, e.output.decode(errors='ignore')
