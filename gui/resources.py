# gui/resources.py
import sys
import os

# Theme colors used by the GUI
COLOR_BG = "#0A0F14"
COLOR_PANEL = "#11181F"
COLOR_TEXT = "#00E5FF"
COLOR_ACCENT = "#00C4FF"
COLOR_BAD = "#FF4C4C"
COLOR_GOOD = "#4CFF4C"
COLOR_INFO = "#4CD3FF"

def resource_path(filename: str) -> str:
    """
    Return absolute path to resource inside 'database/images'.
    Works in development and when bundled with PyInstaller (sys._MEIPASS).
    Always returns path with forward slashes for Qt compatibility.
    """
    try:
        base_path = sys._MEIPASS  # type: ignore
    except Exception:
        base_path = os.path.abspath(".")
    full = os.path.join(base_path, "database", "images", filename)
    return os.path.abspath(full).replace("\\", "/")
