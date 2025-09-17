# scanner/file_readers/binary_reader.py

import os
import re
from utils.logger import log_detection

CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB

# -----------------------------
# Extract human-readable strings from binary
# -----------------------------
def extract_human_strings(file_path, min_len=4):
    """
    Extracts ASCII and UTF-16 LE human-readable strings from a binary file.
    Only strings containing at least one alphabet character are included.
    """
    readable_strings = []
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                # ASCII strings
                ascii_strings = re.findall(b"[ -~]{%d,}" % min_len, chunk)
                for s in ascii_strings:
                    text = s.decode("latin-1", errors="ignore").strip()
                    if any(c.isalpha() for c in text):
                        readable_strings.append(text)

                # UTF-16 LE strings
                utf16_strings = re.findall(b'(?:[ -~]\x00){%d,}' % min_len, chunk)
                for s in utf16_strings:
                    text = s.decode("utf-16le", errors="ignore").strip()
                    if any(c.isalpha() for c in text):
                        readable_strings.append(text)

    except Exception as e:
        log_detection(file_path, f"[binary_reader] Error extracting strings: {e}")

    return readable_strings

# -----------------------------
# Main reader function for heuristic scanning
# -----------------------------
def read_binary_file(file_path):
    """
    Reads a binary file and returns human-readable strings for heuristic scanning.
    Returns:
        dict: {
            'raw_bytes': all extracted strings as a single byte string,
            'strings': list of extracted human-readable strings
        }
    """
    try:
        strings = extract_human_strings(file_path)
        # Combine all strings as bytes for keyword matching in heuristics
        combined_bytes = "\n".join(strings).encode("utf-8", errors="ignore")
        return {
            "raw_bytes": combined_bytes,
            "strings": strings
        }
    except Exception as e:
        log_detection(file_path, f"[binary_reader] Failed to read binary: {e}")
        return {
            "raw_bytes": b"",
            "strings": []
        }
