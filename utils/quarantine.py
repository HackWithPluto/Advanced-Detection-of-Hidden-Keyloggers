import os
import shutil
import tkinter as tk
from tkinter import messagebox
from utils.logger import log_detection  # Make sure logger.py has log_detection

QUARANTINE= os.path.join("database")
QUARANTINE_DIR = os.path.join(QUARANTINE, "quarantine")

# Ensure quarantine directory exists
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

def quarantine_file(file_path, parent=None, ask_user=True, auto_quarantine=False):
    """
    Move a suspicious file to quarantine folder.
    :param file_path: Path to the suspicious file
    :param parent: Tkinter window to attach popup (optional)
    :param ask_user: Whether to ask user before moving
    :param auto_quarantine: If True, move without asking
    :return: Path to quarantined file if moved, else None
    """
    try:
        move_file = auto_quarantine

        # Ask user via GUI if required
        if ask_user and parent:
            move_file = messagebox.askyesno(
                "Quarantine File",
                f"Do you want to move the suspicious file to quarantine?\n{file_path}",
                parent=parent
            )

        if move_file:
            filename = os.path.basename(file_path)
            dest_path = os.path.join(QUARANTINE_DIR, filename)

            # Handle duplicate names
            count = 1
            while os.path.exists(dest_path):
                name, ext = os.path.splitext(filename)
                dest_path = os.path.join(QUARANTINE_DIR, f"{name}_{count}{ext}")
                count += 1

            shutil.move(file_path, dest_path)

            # Log the quarantine action
            log_detection(file_path, f"File quarantined to {dest_path}")

            return dest_path

        return None

    except Exception as e:
        log_detection(file_path, f"Failed to quarantine: {e}")
        return None
