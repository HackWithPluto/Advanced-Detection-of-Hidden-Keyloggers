# main.py
# Entry point for KeyDefender GUI — includes DPI-awareness and quieter Qt logging.
# Replace your existing main.py with this file.

import os
import sys



# Quiet noisy Qt QPA log messages (optional)
os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")

# Let Qt try high-DPI scaling (recommended)
os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

# Windows: try to make the process DPI-aware so Qt receives correct DPI info.
if sys.platform.startswith("win"):
    try:
        import ctypes
        # Try SetProcessDpiAwareness (Windows 8.1+)
        # PROCESS_SYSTEM_DPI_AWARE = 1
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            # fallback to older API
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    except Exception:
        # ignore any failure here; Qt will fallback to 96 DPI
        pass

# --------------------------
# Now import Qt and your GUI
# --------------------------
try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication
except Exception as e:
    print("Failed to import PyQt6. Is it installed in this environment?", file=sys.stderr)
    raise

# These attributes must be set before creating QApplication
try:
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
except Exception:
    # older Qt may not support these attributes — ignore
    pass

# Import the rest of your app (after Qt attributes are set)
try:
    # Import LandingPage from your GUI package
    from gui.landing import LandingPage
except Exception as e:
    print("Error importing GUI module 'gui.landing':", file=sys.stderr)
    raise

def main():
    # Create application and show UI
    app = QApplication(sys.argv)
    # Optional: set application name / icon / style here
    try:
        app.setApplicationName("KeyDefender")
    except Exception:
        pass

    try:
        window = LandingPage()
        window.show()
        # If you used showMaximized + setFixedSize in LandingPage, that will take effect
    except Exception as e:
        print("Failed to instantiate LandingPage:", file=sys.stderr)
        raise

    # Run Qt event loop
    try:
        exit_code = app.exec()
    except Exception as e:
        print("Error while running Qt event loop:", e, file=sys.stderr)
        exit_code = 1
    # ensure a clean python exit
    sys.exit(exit_code)

# at tool startup
try:
    from scanner.realtime_scanner import start_scanner
    start_scanner()   # autoruns scanner in background
except Exception:
    pass

if __name__ == "__main__":
    main()
