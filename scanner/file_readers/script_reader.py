# scanner/file_readers/scripts_reader.py

import os
import re
import base64

# -----------------------------
# Supported script/text extensions
# -----------------------------
SCRIPT_EXTENSIONS = (
    ".py", ".pyw", ".js", ".vbs", ".ps1",
    ".sh", ".pl", ".rb", ".txt", ".log"
)

# -----------------------------
# Obfuscation patterns
# -----------------------------
OBFUSCATION_PATTERNS = [
    r"chr\(\d+\)", r"String.fromCharCode\(\d+\)", r"eval\(", r"exec\("
]

# -----------------------------
# File reading
# -----------------------------
def read_file(file_path):
    """
    Read script or text file safely and return raw content.
    """
    text_content = ""
    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in SCRIPT_EXTENSIONS:
            return text_content

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text_content = f.read()

    except Exception as e:
        print(f"[scripts_reader] Error reading {file_path}: {e}")

    return text_content

# -----------------------------
# Preprocessing
# -----------------------------
def preprocess_text(text):
    # Remove common comments
    text = re.sub(r"#.*", "", text)       # Python, Shell, Ruby
    text = re.sub(r"//.*", "", text)      # JS, C-style
    text = re.sub(r";.*", "", text)       # VBS, PowerShell
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)  # HTML/JS embedded
    # Normalize line endings
    return text.replace("\r\n", "\n").replace("\r", "\n")

# -----------------------------
# Decode Base64 strings
# -----------------------------
def decode_base64_strings(text):
    decoded = []
    for b64 in re.findall(r"[A-Za-z0-9+/=]{8,}", text):
        try:
            decoded_text = base64.b64decode(b64).decode("utf-8", errors="ignore")
            decoded.append(decoded_text)
        except:
            pass
    return decoded

# -----------------------------
# Detect obfuscation
# -----------------------------
def detect_obfuscation(text):
    matches = []
    for pattern in OBFUSCATION_PATTERNS:
        matches.extend(re.findall(pattern, text, flags=re.IGNORECASE))
    return matches

# -----------------------------
# Advanced file reader
# -----------------------------
def read_file_advanced(file_path):
    """
    Read file with preprocessing, decoding, and obfuscation detection.
    Returns a string ready for heuristic analysis.
    """
    text_content = read_file(file_path)
    if not text_content:
        return ""

    text_content = preprocess_text(text_content)

    # Include decoded Base64 strings
    decoded_texts = decode_base64_strings(text_content)
    for dt in decoded_texts:
        text_content += "\n" + dt

    # Include obfuscation matches as pseudo-text for heuristic
    obf_matches = detect_obfuscation(text_content)
    if obf_matches:
        text_content += "\n" + "\n".join(obf_matches)

    return text_content
