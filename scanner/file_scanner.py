# scanner/file_scanner.py

import os
from utils.logger import log_detection
from utils.quarantine import quarantine_file
from scanner.heuristic import detect_file
from scanner.file_readers import archive_reader

# -----------------------------
# Supported file types
# -----------------------------
SUPPORTED= (
    ".py", ".pyw", ".js", ".vbs", ".ps1", ".sh", ".pl", ".rb",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".pdf",
    ".png", ".jpg", ".jpeg", ".bmp", ".gif",
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".msi",
    ".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tar.bz2", ".csv"
)

# -----------------------------
# Scan a single file
# -----------------------------
def scan_file(file_path, quarantine_prompt=True):
    ext = os.path.splitext(file_path)[1].lower()

    try:
        # -----------------------------
        # If archive, use archive_reader recursively
        # -----------------------------
        if ext in [".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tar.bz2"]:
            return archive_reader.read_archive_file(file_path, quarantine_prompt=quarantine_prompt)

        # -----------------------------
        # Detect using heuristic (readers handled internally)
        # -----------------------------
        verdict, matches = detect_file(file_path)

        # -----------------------------
        # Determine action and log
        # -----------------------------
        action = "none"
        if "Keylogger Detected" in verdict or "Suspicious" in verdict:
            log_detection(file_path, verdict)
            if quarantine_prompt:
                action = "prompt"
            else:
                quarantined_path = quarantine_file(file_path)
                action = "quarantined" if quarantined_path else "none"
            status = "suspicious"
        else:
            log_detection(file_path, verdict)
            status = "clean"

        return {
            "file": file_path,
            "status": status,
            "action": action,
            "verdict": verdict,
            "matches": matches
        }

    except Exception as e:
        log_detection(file_path, f"Error scanning file: {e}")
        return {
            "file": file_path,
            "status": "error",
            "action": "none",
            "verdict": f"Error: {e}",
            "matches": []
        }


# -----------------------------
# Scan folder recursively
# -----------------------------
def scan_folder(folder_path, recursive=True, quarantine_prompt=True):
    results = []

    for root_dir, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root_dir, file)
            ext = os.path.splitext(file_path)[1].lower()

            if ext in SUPPORTED:
                result = scan_file(file_path, quarantine_prompt=quarantine_prompt)
                results.append(result)

        if not recursive:
            break

    return results
