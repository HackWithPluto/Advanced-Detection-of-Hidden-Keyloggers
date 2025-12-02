# gui/autoscan_result.py
import os
import html
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QTextEdit
from PyQt6.QtGui import QTextCursor
from PyQt6.QtCore import QTimer

from .resources import (
    COLOR_BG, COLOR_PANEL, COLOR_TEXT, COLOR_ACCENT,
    COLOR_BAD, COLOR_GOOD, COLOR_INFO
)

AUTOSCAN_LOG_PATH = os.path.join("database", "logs", "autoscan_logs.txt")


class AutoScanResultWindow(QDialog):
    def __init__(self, parent=None, log_path=None, auto_refresh_ms: int = 2000):
        super().__init__(parent)
        self.setWindowTitle("AutoScan Results")
        self.resize(900, 550)
        self.setModal(False)
        self.setStyleSheet(f"background-color:{COLOR_BG}; color:{COLOR_TEXT};")

        self.log_path = log_path or AUTOSCAN_LOG_PATH
        self.auto_refresh_ms = int(auto_refresh_ms)

        layout = QVBoxLayout(self)

        title = QLabel("AutoScan Logs (latest run)")
        title.setStyleSheet(f"color:{COLOR_ACCENT}; font-size:22px;")
        layout.addWidget(title)

        # QTextEdit used for HTML colored monospace rendering
        self.terminal = QTextEdit()
        self.terminal.setReadOnly(True)
        # monospace + dark panel background to match ScanPage
        self.terminal.setStyleSheet(
            f"""
            background-color:{COLOR_PANEL};
            color:{COLOR_TEXT};
            font-family: Consolas, "Courier New", monospace;
            font-size:14px;
            """
        )
        layout.addWidget(self.terminal)

        # Manual exit for convenience
        btn_exit = QPushButton("Exit")
        btn_exit.clicked.connect(self.close)
        layout.addWidget(btn_exit)

        # Auto-refresh timer
        self.timer = QTimer(self)
        
        self.timer.timeout.connect(self.load_logs)
        if self.auto_refresh_ms > 0:
            self.timer.start(self.auto_refresh_ms)

        # initial load
        self.load_logs()

    def closeEvent(self, event):
        # stop timer to avoid callbacks after destruction
        try:
            if hasattr(self, "timer") and self.timer.isActive():
                self.timer.stop()
        except Exception:
            pass
        super().closeEvent(event)

    def _render_full_colored_line(self, path: str, result: str):
        """
        Render entire line in monospace with single color:
            <path> → <result>
        If result contains 'keylogger detected' -> red bold
        If result contains 'normal file' -> green
        Else -> default text color
        """
        try:
            p = html.escape(path)
            r = html.escape(result)
            # decide color and weight
            lower = result.lower()
            if "keylogger detected" in lower or "detected" in lower:
                color = COLOR_BAD
                weight = "font-weight:bold;"
            elif "normal file" in lower or "clean" in lower:
                color = COLOR_GOOD
                weight = ""
            elif result.strip().startswith("---") or "info" in lower:
                color = COLOR_INFO
                weight = ""
            else:
                color = COLOR_TEXT
                weight = ""

            # Compose full-line HTML using <pre> to preserve spacing & monospace look
            html_line = (
                f"<pre style='margin:0; white-space:pre; font-family:Consolas, \"Courier New\", monospace; font-size:14px;'>"
                f"<span style='color:{color}; {weight}'>{p} → {r}</span>"
                f"</pre>"
            )
            self.terminal.insertHtml(html_line)
            self.terminal.insertPlainText("\n")
        except Exception:
            try:
                self.terminal.insertPlainText(f"{path} → {result}\n")
            except Exception:
                pass

    def load_logs(self):
        """Load autoscan logs and render each line in exact full-line coloring format."""
        try:
            self.terminal.clear()
        except Exception:
            pass

        if not os.path.exists(self.log_path):
            try:
                self.terminal.setPlainText("No autoscan logs found.")
            except Exception:
                pass
            return

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines() or []

            for ln in lines:
                # trim newline but preserve inner spacing
                line = ln.rstrip("\n")
                if not line:
                    self.terminal.insertPlainText("\n")
                    continue

                # Expect format: "<path> → <result>"
                if "→" in line:
                    parts = line.split("→", 1)
                    path = parts[0].strip()
                    result = parts[1].strip()
                    self._render_full_colored_line(path, result)
                else:
                    # fallback: color based on keywords
                    lower = line.lower()
                    if "keylogger" in lower or "detected" in lower or "error" in lower:
                        self._render_full_colored_line(line, "keylogger detected")
                    elif "normal" in lower or "clean" in lower:
                        self._render_full_colored_line(line, "normal file")
                    else:
                        # plain
                        self.terminal.insertPlainText(line + "\n")

            # auto-scroll
            try:
                self.terminal.moveCursor(QTextCursor.MoveOperation.End)
            except Exception:
                pass

        except Exception:
            try:
                self.terminal.setPlainText("Failed to load autoscan logs.")
            except Exception:
                pass
