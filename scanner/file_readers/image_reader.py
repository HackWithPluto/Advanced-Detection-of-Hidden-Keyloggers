# scanner/file_readers/image_reader.py

import os
import re
import base64
from PIL import Image
from utils.logger import log_detection

# -----------------------------
# Decode Base64 strings
# -----------------------------
def decode_base64_strings(data):
    decoded = ""
    try:
        patterns = re.findall(r'[A-Za-z0-9+/=]{20,}', data)
        for p in patterns:
            try:
                b = base64.b64decode(p, validate=True)
                decoded += b.decode("latin-1", errors="ignore") + "\n"
            except:
                continue
    except Exception as e:
        log_detection("[image_reader]", f"Base64 decode error: {e}")
    return decoded

# -----------------------------
# Extract metadata from image
# -----------------------------
def extract_metadata(file_path):
    metadata_text = ""
    try:
        img = Image.open(file_path)
        for key, value in img.info.items():
            metadata_text += f"{key}: {value}\n"
        metadata_text += decode_base64_strings(metadata_text)
    except Exception as e:
        log_detection(file_path, f"[image_reader] Metadata extraction error: {e}")
    return metadata_text

# -----------------------------
# Extract raw bytes from image
# -----------------------------
def extract_raw_bytes(file_path):
    raw_text = ""
    try:
        with open(file_path, "rb") as f:
            content_bytes = f.read()
            # Convert bytes to string safely
            raw_text += content_bytes.decode("latin-1", errors="ignore")
            raw_text += decode_base64_strings(raw_text)
    except Exception as e:
        log_detection(file_path, f"[image_reader] Raw bytes extraction error: {e}")
    return raw_text

# -----------------------------
# Main image reader
# -----------------------------
def read_image_file(file_path):
    content = ""
    # Metadata
    content += extract_metadata(file_path)
    # Raw bytes
    content += extract_raw_bytes(file_path)
    return content
