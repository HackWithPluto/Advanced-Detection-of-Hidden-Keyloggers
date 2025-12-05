import os
import sys

os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")
os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

if sys.platform.startswith("win"):
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    except Exception:
        pass
try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication
except Exception as e:
    print("Failed to import PyQt6. Is it installed in this environment?", file=sys.stderr)
    raise

try:
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
except Exception:
    pass

try:
    from gui.landing import LandingPage
except Exception as e:
    print("Error importing GUI module 'gui.landing':", file=sys.stderr)
    raise

def main():
    app = QApplication(sys.argv)
    try:
        app.setApplicationName("KeyDefender")
    except Exception:
        pass
    try:
        window = LandingPage()
        window.show()
    except Exception as e:
        print("Failed to instantiate LandingPage:", file=sys.stderr)
        raise
    try:
        exit_code = app.exec()
    except Exception as e:
        print("Error while running Qt event loop:", e, file=sys.stderr)
        exit_code = 1
    sys.exit(exit_code)

try:
    from scanner.realtime_scanner import start_scanner
    start_scanner()
except Exception:
    pass

if __name__ == "__main__":
    main()
