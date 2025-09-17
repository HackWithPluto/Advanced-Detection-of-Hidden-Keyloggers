def read_archive_file(file_path, quarantine_prompt=True):
    from scanner import file_scanner
    import tempfile, os, shutil, zipfile, tarfile, rarfile
    from utils.logger import log_detection

    results = []
    temp_dir = tempfile.mkdtemp(prefix="archive_scan_")

    try:
        # -----------------------------
        # Extract archive
        # -----------------------------
        if file_path.lower().endswith(".zip"):
            with zipfile.ZipFile(file_path, "r") as zf:
                zf.extractall(temp_dir)

        elif file_path.lower().endswith((".tar", ".tar.gz", ".tar.bz2")):
            with tarfile.open(file_path, "r:*") as tf:
                tf.extractall(temp_dir)

        elif file_path.lower().endswith(".rar"):
            with rarfile.RarFile(file_path, "r") as rf:
                rf.extractall(temp_dir)

        # -----------------------------
        # Temporarily replace logger
        # -----------------------------
        original_log_detection = file_scanner.log_detection
        file_scanner.log_detection = lambda *a, **k: None  # disable temp logs

        # -----------------------------
        # Scan extracted files
        # -----------------------------
        for root, _, files in os.walk(temp_dir):
            for f in files:
                extracted_file_path = os.path.join(root, f)
                relative_inside = os.path.relpath(extracted_file_path, temp_dir)
                display_path = f"{os.path.abspath(file_path)} → {relative_inside}"

                try:
                    scan_result = file_scanner.scan_file(extracted_file_path, quarantine_prompt=quarantine_prompt)
                    scan_result["file"] = display_path
                    log_detection(display_path, scan_result["verdict"])  # ✅ only archive path
                    results.append(scan_result)

                except Exception as e:
                    log_detection(display_path, f"Error scanning extracted file: {e}")

        # -----------------------------
        # Restore logger
        # -----------------------------
        file_scanner.log_detection = original_log_detection

    except Exception as e:
        log_detection(file_path, f"Error reading archive: {e}")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return results
