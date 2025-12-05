# gui/autoscan_result.py

import html

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QTextEdit
from PyQt6.QtGui import QTextCursor
from PyQt6.QtCore import QTimer

from .resources import (
    COLOR_BG, COLOR_PANEL, COLOR_TEXT, COLOR_ACCENT,
    COLOR_BAD, COLOR_GOOD, COLOR_INFO
)

# NEW: import the in-memory autoscan log accessor
from scanner.autoscan import get_autoscan_log_snapshot


class AutoScanResultWindow(QDialog):
    """
    AutoScan Results window.

    Updated to work with the **in-memory** autoscan logging:
      - Reads entries from scanner.autoscan.get_autoscan_log_snapshot()
      - Does NOT touch any autoscan log file on disk
      - Auto-refreshes every `auto_refresh_ms` milliseconds
    """

    def __init__(self, parent=None, log_path=None, auto_refresh_ms: int = 2000):
        super().__init__(parent)
        self.setWindowTitle("AutoScan Results")
        self.resize(900, 550)
        self.setModal(False)
        self.setStyleSheet(f"background-color:{COLOR_BG}; color:{COLOR_TEXT};")

        # log_path kept only for backward-compat, not used anymore
        self.auto_refresh_ms = int(auto_refresh_ms)

        layout = QVBoxLayout(self)

        title = QLabel("AutoScan Logs (current session)")
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

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def _map_status_to_result(self, status: str) -> str:
        """
        Map raw engine status to user-facing text,
        to keep behaviour similar to the old autoscan log format.
        """
        try:
            s = (status or "").strip().lower()
        except Exception:
            return str(status)

        if s in ("suspicious", "detected", "malicious"):
            return "keylogger detected"
        if s in ("clean", "good", "ok"):
            return "normal file"
        return status

    def _render_full_colored_line(self, path: str, result: str):
        """
        Render entire line in monospace with single color:
            <path> → <result>

        If result contains 'keylogger detected' -> red bold
        If result contains 'normal file'        -> green
        Else                                    -> default text color
        """
        try:
            p = html.escape(path)
            r = html.escape(result)
            # decide color and weight
            lower = (result or "").lower()
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
                f"<pre style='margin:0; white-space:pre; "
                f"font-family:Consolas, \"Courier New\", monospace; font-size:14px;'>"
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

    def _render_message_line(self, text: str, level: str = "info"):
        """
        Render a generic message line (no path/result format).
        Used for:
          - '===== AutoScan Started ====='
          - warnings, errors, info messages
        """
        try:
            t = html.escape(text or "")
            lvl = (level or "info").lower()

            # Choose color
            if lvl in ("error", "critical"):
                color = COLOR_BAD
            elif lvl in ("warning", "warn"):
                color = COLOR_INFO  # or COLOR_BAD if you prefer
            else:
                # fallback based on keywords
                lower = t.lower()
                if "error" in lower or "failed" in lower:
                    color = COLOR_BAD
                elif "warning" in lower:
                    color = COLOR_INFO
                else:
                    color = COLOR_TEXT

            html_line = (
                f"<pre style='margin:0; white-space:pre; "
                f"font-family:Consolas, \"Courier New\", monospace; font-size:14px;'>"
                f"<span style='color:{color};'>{t}</span>"
                f"</pre>"
            )
            self.terminal.insertHtml(html_line)
            self.terminal.insertPlainText("\n")
        except Exception:
            try:
                self.terminal.insertPlainText(text + "\n")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Main loader: now reads from in-memory autoscan log buffer
    # ------------------------------------------------------------------

    def load_logs(self):
        """Load autoscan logs from in-memory buffer and render them."""
        try:
            self.terminal.clear()
        except Exception:
            pass

        try:
            entries = get_autoscan_log_snapshot()
        except Exception:
            entries = []

        if not entries:
            try:
                self.terminal.setPlainText("No autoscan logs available for this session.")
            except Exception:
                pass
            return

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            etype = entry.get("type", "").lower()

            # ---------------- file entries ----------------
            if etype == "file":
                file_path = entry.get("file", "Unknown file")
                raw_status = entry.get("status", "unknown")
                mapped_status = self._map_status_to_result(raw_status)
                self._render_full_colored_line(file_path, mapped_status)

            # ---------------- message entries ----------------
            elif etype == "message":
                text = entry.get("text", "")
                level = entry.get("level", "info")
                self._render_message_line(text, level=level)

            # ---------------- fallback ----------------
            else:
                # Unknown entry type → plain text dump
                try:
                    self.terminal.insertPlainText(str(entry) + "\n")
                except Exception:
                    pass

        # auto-scroll to bottom
        try:
            self.terminal.moveCursor(QTextCursor.MoveOperation.End)
        except Exception:
            pass
