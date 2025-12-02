import os
from scanner.heuristic import detect_file
from utils.quarantine import quarantine_file
from utils.logger import log_detection

def analyze_file(file_path, parent=None, ask_quarantine=True):
    """
    Analyze any file using heuristic detection from heuristic.py.
    Returns a detailed dict including verdict, matches, and status.
    Can prompt for quarantine if suspicious.
    
    Parameters:
        file_path (str): Path of the file to analyze
        parent (tkinter window): Optional parent window for quarantine popup
        ask_quarantine (bool): Whether to ask before moving to quarantine
    
    Returns:
        dict: {
            "file": file_path,
            "verdict": str,
            "matches": list,
            "status": str,
            "action": str (quarantined/none)
        }
    """
    try:
        # Run heuristic detection
        verdict, matches = detect_file(file_path)

        # Determine status based on verdict
        if "Keylogger Detected" in verdict or "Suspicious" in verdict:
            status = "suspicious"
            action = None
            # Ask for quarantine
            if ask_quarantine:
                quarantined_path = quarantine_file(file_path, parent=parent, ask_user=True)
                action = "quarantined" if quarantined_path else "none"
        elif "Low Suspicion" in verdict:
            status = "low_suspicion"
            action = None
        else:
            status = "clean"
            action = None

        # Log the detection
        log_detection(file_path, verdict)
        if action == "quarantined":
            log_detection(file_path, f"Quarantined → {quarantined_path}")

        return {
            "file": file_path,
            "verdict": verdict,
            "matches": matches,
            "status": status,
            "action": action or "none"
        }

    except Exception as e:
        log_detection(file_path, f"Error analyzing file: {e}")
        return {
            "file": file_path,
            "verdict": f"Error: {e}",
            "matches": [],
            "status": "error",
            "action": "none"
        }
