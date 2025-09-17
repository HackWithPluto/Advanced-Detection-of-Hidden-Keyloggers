# scanner/file_readers/office_reader.py
import zipfile
import base64
import re
from utils.logger import log_detection


def decode_base64_strings(text):
    """
    Detect and decode base64-like strings inside text.
    """
    decoded = ""
    try:
        patterns = re.findall(r"[A-Za-z0-9+/=]{20,}", text)
        for p in patterns:
            try:
                b = base64.b64decode(p, validate=True)
                decoded += b.decode("latin-1", errors="ignore") + "\n"
            except Exception:
                continue
    except Exception as e:
        log_detection("[office_reader]", f"Base64 decode error: {e}")
    return decoded


def read_office_file(file_path):
    """
    Extracts macro and embedded object content from Office files.
    Supports: .docx, .docm, .xlsx, .pptx (ZIP-based formats).
    Returns decoded text for further scanning.
    """
    content = ""
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as z:
                # Ensure only strings are processed
                names = [n for n in z.namelist() if isinstance(n, str)]

                # --- Macros (vbaProject.bin) ---
                macro_paths = [p for p in names if "vbaproject.bin" in p.lower()]
                for m in macro_paths:
                    try:
                        data = z.read(m)
                        text = data.decode("latin-1", errors="ignore")
                        content += f"\n--- Macro {m} ---\n{text}\n"
                        content += decode_base64_strings(text)
                    except Exception as e:
                        log_detection(file_path, f"[office_reader] Failed reading macro {m}: {e}")

                # --- Embedded objects ---
                embedded_paths = [
                    p for p in names if "embeddings/" in p.lower() or "object" in p.lower()
                ]
                for e in embedded_paths:
                    try:
                        data = z.read(e)
                        try:
                            text = data.decode("latin-1", errors="ignore")
                            content += f"\n--- Embedded {e} ---\n{text}\n"
                            content += decode_base64_strings(text)
                        except Exception:
                            # Binary payload → just log size
                            content += f"\n--- Embedded binary {e} (size={len(data)} bytes) ---\n"
                    except Exception as e2:
                        log_detection(file_path, f"[office_reader] Failed reading embedded {e}: {e2}")

    except Exception as e:
        log_detection(file_path, f"[office_reader] General error: {e}")
    return content
