# utils/quarantine.py
import os
import shutil
import threading

# Global mode flag - when True, do NOT show any GUI dialogs and perform silent quarantine
SILENT_QUARANTINE = False
_SILENT_LOCK = threading.Lock()

def set_quarantine_silent_mode(enabled: bool):
    """
    Enable/disable global silent-mode for quarantine operations.
    When enabled True: quarantine operations will not prompt GUI dialogs.
    """
    global SILENT_QUARANTINE
    with _SILENT_LOCK:
        SILENT_QUARANTINE = bool(enabled)

def is_quarantine_silent() -> bool:
    global SILENT_QUARANTINE
    with _SILENT_LOCK:
        return bool(SILENT_QUARANTINE)

def quarantine_file(path: str, parent=None, ask_user=True, quarantine_dir: str = "database/quarantine"):
    """
    Move file into quarantine folder.
    Behavior:
      - If global SILENT_QUARANTINE is True, will NOT ask user and will perform silent move.
      - If ask_user is True and SILENT_QUARANTINE is False, this function returns False (preserve existing UI flow).
        The higher-level GUI code is expected to handle interactive confirmation and then call this function with ask_user=False.
      - Returns True on success, False otherwise.
    """
    try:
        # Force ask_user False if silent mode enabled
        if is_quarantine_silent():
            ask_user = False

        # If interactive/ask_user is requested, do not perform silent move here
        # (keeps older interactive flow in GUI code)
        if ask_user:
            return False

        # Ensure quarantine directory exists
        try:
            os.makedirs(quarantine_dir, exist_ok=True)
        except Exception:
            pass

        # Build destination path
        base = os.path.basename(path)
        dest = os.path.join(quarantine_dir, base)

        # If dest exists, append numeric suffix
        if os.path.exists(dest):
            root, ext = os.path.splitext(base)
            i = 1
            candidate = dest
            while os.path.exists(candidate):
                candidate = os.path.join(quarantine_dir, f"{root}_{i}{ext}")
                i += 1
            dest = candidate

        # Try to move
        try:
            shutil.move(path, dest)
            return True
        except Exception:
            # fallback copy+remove
            try:
                shutil.copy2(path, dest)
                try:
                    os.remove(path)
                except Exception:
                    pass
                return True
            except Exception:
                return False

    except Exception:
        return False
