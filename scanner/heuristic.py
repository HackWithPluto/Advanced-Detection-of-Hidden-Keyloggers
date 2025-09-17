# scanner/heuristic.py

import re
from scanner.data.keywords import KEYWORDS, BEHAVIOR_PATTERNS
from scanner.file_readers import (
    script_reader,
    office_reader,
    pdf_reader,
    image_reader,
    binary_reader,
    archive_reader
)

# -----------------------------
# Helper: Count matches in text or bytes
# -----------------------------
def count_matches(patterns, text, is_regex=False):
    matches = []
    for p in patterns:
        if is_regex:
            if re.search(p, text, re.IGNORECASE):
                matches.append(p)
        else:
            if p.lower() in text.lower():
                matches.append(p)
    return matches

def count_matches_bytes(patterns, content_bytes):
    matches = []
    for p in patterns:
        if isinstance(p, bytes):
            if p in content_bytes:
                matches.append(p.decode(errors="ignore"))
        else:
            if p.encode() in content_bytes:
                matches.append(p)
    return matches

# -----------------------------
# Main detection using readers
# -----------------------------
def detect_file(file_path, threshold=5):
    """
    Full detection function for all supported file types.
    Returns: (verdict, matches)
    """
    ext = file_path.split(".")[-1].lower()
    all_matches = []
    text_content = ""
    content_bytes = b""

    try:
        # -----------------------------
        # SCRIPT FILES
        # -----------------------------
        if ext in ["py", "pyw", "js", "vbs", "ps1", "sh", "rb", "pl"]:
            text_content = script_reader.read_file(file_path)
            all_matches.extend(count_matches(KEYWORDS.get(ext, []), text_content))

        # -----------------------------
        # OFFICE FILES scanner with python keywords
        # -----------------------------
        elif ext in ["doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf","csv"]:
            text_content = office_reader.read_office_file(file_path)
            all_matches.extend(count_matches(KEYWORDS.get("py", []), text_content))

        # -----------------------------
        # PDF FILES
        # -----------------------------
        elif ext == "pdf":
            text_content = pdf_reader.read_pdf_file(file_path)
            all_matches.extend(count_matches(KEYWORDS.get("pdf", []), text_content))

        # -----------------------------
        # IMAGES
        # -----------------------------
        elif ext in ["png", "jpg", "jpeg", "bmp", "gif"]:
            text_content = image_reader.read_image_file(file_path)
            all_matches.extend(count_matches(KEYWORDS.get("py", []), text_content))

        # -----------------------------
        # BINARY FILES (human-readable strings only)
        # -----------------------------
        elif ext in ["exe", "dll", "scr", "bat", "cmd", "com", "msi"]:
            try:
                bin_data = binary_reader.read_binary_file(file_path)
                content_bytes = bin_data["raw_bytes"]
                readable_strings = bin_data["strings"]

                # Only keylogger-specific keyword matches from py keyword list (not from exe beacuse exe compiled from python script )
                all_matches.extend(count_matches_bytes(KEYWORDS.get("py", []), content_bytes))

            
            except Exception as e:
                from utils.logger import log_detection
                log_detection(file_path, f"[heuristic] Error reading binary: {e}")

        # -----------------------------
        # ARCHIVE FILES
        # -----------------------------
        elif ext in ["zip", "rar", "7z", "tar", "tar.gz", "tar.bz2"]:
            all_matches.extend(archive_reader.read_archive(file_path))  # internally calls detect_file

        # -----------------------------
        # OTHER FILES
        # -----------------------------
        else:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    text_content = f.read()
                    all_matches.extend(count_matches(BEHAVIOR_PATTERNS, text_content))
            except:
                with open(file_path, "rb") as f:
                    content_bytes = f.read()
                    all_matches.extend(count_matches_bytes(BEHAVIOR_PATTERNS, content_bytes))

        # -----------------------------
        # Determine verdict
        # -----------------------------
        match_count = len(all_matches)
        if match_count >= 10:
            verdict = f"Keylogger Detected ({match_count} suspicious patterns)"
        elif match_count >= 7:
            verdict = f"Suspicion ({match_count} patterns)"
        elif match_count >= 5:
            verdict = f"Normal ({match_count} patterns)"
        else:
            verdict = "Clean (0 matches)"

        return verdict, all_matches

    except Exception as e:
        return f"Error scanning file: {e}", []
