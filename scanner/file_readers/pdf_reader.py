import PyPDF2
import re
import base64
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
        log_detection("[pdf_reader]", f"Base64 decode error: {e}")
    return decoded

# -----------------------------
# Extract embedded JavaScript and files
# -----------------------------
def extract_embedded_content(file_path):
    extracted_content = ""
    try:
        with open(file_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)

            # Loop through pages to access indirect objects
            for page in reader.pages:
                try:
                    # Extract /AA and /OpenAction
                    for action_key in ("/AA", "/OpenAction"):
                        if action_key in page:
                            action = page[action_key]
                            data = str(action)
                            extracted_content += data + "\n"
                            extracted_content += decode_base64_strings(data)
                except:
                    continue

            # Check for embedded files
            if "/Names" in reader.trailer["/Root"]:
                names = reader.trailer["/Root"]["/Names"]
                if "/EmbeddedFiles" in names:
                    ef_names = names["/EmbeddedFiles"]["/Names"]
                    for i in range(0, len(ef_names), 2):
                        try:
                            file_spec = ef_names[i+1].get_object()
                            data = file_spec["/EF"]["/F"].get_data().decode("latin-1", errors="ignore")
                            extracted_content += data + "\n"
                            extracted_content += decode_base64_strings(data)
                        except:
                            continue

            # Extract JavaScript
            if "/Names" in reader.trailer["/Root"]:
                names = reader.trailer["/Root"]["/Names"]
                if "/JavaScript" in names:
                    js_names = names["/JavaScript"]["/Names"]
                    for i in range(0, len(js_names), 2):
                        try:
                            js_obj = js_names[i+1].get_object()
                            js_code = js_obj.get("/JS") or js_obj.get("/JavaScript")
                            if isinstance(js_code, PyPDF2.generic.StreamObject):
                                js_code = js_code.get_data().decode("latin-1", errors="ignore")
                            extracted_content += js_code + "\n"
                            extracted_content += decode_base64_strings(js_code)
                        except:
                            continue

    except Exception as e:
        log_detection(file_path, f"[pdf_reader] Embedded content extraction error: {e}")

    return extracted_content

# -----------------------------
# Main PDF reader
# -----------------------------
def read_pdf_file(file_path):
    return extract_embedded_content(file_path)
