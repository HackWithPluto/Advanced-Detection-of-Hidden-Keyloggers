# gui/landing.py (modified — Settings button removed)
import os
import json
import time
import threading
import subprocess
import sys

from PyQt6.QtCore import Qt, QTimer, QThread
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QSizePolicy, QDialog,
    QFileDialog, QGraphicsDropShadowEffect
)

from .resources import (
    COLOR_BG, COLOR_PANEL, COLOR_TEXT, COLOR_ACCENT,
    resource_path
)
from .scanpage import ScanPage
from .autoscan_result import AutoScanResultWindow
from .scan_workers import AutoScanWorker
from .external_drive_monitor import ExternalDriveMonitor  # Qt-native monitor


class LandingPage(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KeyDefender — Advanced Detection of Hidden Keyloggers")

        # Initial size
        self.resize(1200, 720)
        self.setMinimumSize(1000, 620)

        # Show maximized and keep that state (remove brittle setFixedSize)
        self.showMaximized()
        # disable maximize button if desired (keeps UI choice from original)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, False)
        # ensure Qt knows we want the maximized window state
        self.setWindowState(self.windowState() | Qt.WindowState.WindowMaximized)

        # container
        self.wrapper = QWidget()
        self.wrapper.setObjectName("bg_wrapper")
        self.setCentralWidget(self.wrapper)

        wrapper_layout = QVBoxLayout(self.wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        self.central = QWidget()
        self.central.setObjectName("central_content")
        wrapper_layout.addWidget(self.central)

        outer = QHBoxLayout(self.central)
        outer.setContentsMargins(100, 60, 80, 40)
        outer.setSpacing(30)

        # left column
        left_col = QWidget()
        left_col.setObjectName("left_col")
        left_layout = QHBoxLayout(left_col)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(18)

        # decorative squares
        decor = QWidget()
        decor_layout = QVBoxLayout(decor)
        decor_layout.setContentsMargins(0, 6, 8, 6)
        decor_layout.setSpacing(12)

        for _ in range(8):
            sq = QFrame()
            sq.setFixedSize(36, 36)
            sq.setStyleSheet(
                "background: rgba(255,255,255,0.03);"
                "border: 2px solid rgba(0,229,255,0.15);"
                "border-radius: 4px;"
            )
            decor_layout.addWidget(sq, alignment=Qt.AlignmentFlag.AlignTop)

        left_layout.addWidget(decor, alignment=Qt.AlignmentFlag.AlignTop)

        # main button column
        btn_col = QWidget()
        btn_col.setObjectName("btn_col")
        btn_layout = QVBoxLayout(btn_col)
        btn_layout.setContentsMargins(14, 6, 0, 6)
        btn_layout.setSpacing(14)

        # heading
        heading = QLabel("KeyDefender")
        heading.setStyleSheet(
            f"""
            color: {COLOR_ACCENT};
            font-size: 48px;
            font-weight: bold;
            font-family: "Aldhabi";
            """
        )
        heading.setContentsMargins(6, 0, 0, 18)
        btn_layout.addWidget(heading, alignment=Qt.AlignmentFlag.AlignTop)

        BTN_STYLE_SOLID = f"""
        QPushButton {{
            background-color: rgba(0,0,0,0.75);
            color: {COLOR_ACCENT};
            border: 2px solid {COLOR_ACCENT};
            border-radius: 18px;
            font-family: "Aldhabi";
            font-size: 20px;
            font-weight: bold;
            padding: 8px 20px;
            min-width: 260px;
            max-width: 300px;
            height: 44px;
            text-align: center;
        }}
        QPushButton:hover {{
            background-color: rgba(20,20,20,0.90);
            border: 2px solid rgba(0,255,255,0.90);
            color: white;
        }}
        QPushButton:pressed {{
            background-color: rgba(30,30,30,1.00);
            border: 2px solid rgba(0,255,255,1);
            color: white;
        }}
        """

        def add_btn(text, func):
            btn = QPushButton(text)
            btn.setStyleSheet(BTN_STYLE_SOLID)
            btn.setFixedHeight(44)
            try:
                btn.setFont(QFont("Aldhabi", 20, QFont.Weight.Bold))
            except Exception:
                pass
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(func)
            btn_layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignLeft)

            glow = QGraphicsDropShadowEffect(btn)
            glow.setBlurRadius(28)
            glow.setOffset(0, 0)
            glow.setColor(QColor(0, 200, 255, 140))
            btn.setGraphicsEffect(glow)
            return btn

        add_btn("Scan File", self.scan_file)
        add_btn("Scan Folder", self.scan_folder)
        add_btn("System Scan", self.scan_processes)
        add_btn("AutoScan Results", self.view_autoscan_results)
        add_btn("Exit", self.close)
        # Settings button intentionally removed

        btn_layout.addStretch()
        left_layout.addWidget(btn_col, alignment=Qt.AlignmentFlag.AlignTop)
        outer.addWidget(left_col, stretch=0)

        # right spacer
        right_spacer = QWidget()
        right_spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        outer.addWidget(right_spacer, stretch=1)

        # background
        self.apply_background_cover()

        # holders
        self._autoscan_window = None
        self._autoscan_threads = []  # list of tuples (QThread, worker)

        # start autoscan timer/monitor (existing behavior)
        try:
            self._init_autoscan_timer_and_monitor()
        except Exception:
            pass

        # start external drive monitor (Qt-native)
        try:
            self._external_drive_monitor = ExternalDriveMonitor(poll_interval=2.0)
            self._external_drive_monitor.driveDetected.connect(self._on_external_drive_detected)
            self._external_drive_monitor.start()
        except Exception:
            self._external_drive_monitor = None

    # ---------- Background Image ----------
    def apply_background_cover(self):
        bg_path = resource_path("background.png")
        if not os.path.exists(bg_path):
            self.wrapper.setStyleSheet(f"background-color: {COLOR_BG};")
            self.central.setStyleSheet("background-color: transparent;")
            return

        self.wrapper.setStyleSheet(
            f'''
            #bg_wrapper {{
                background-image: url("{bg_path}");
                background-repeat: no-repeat;
                background-position: center right;
                background-color: {COLOR_BG};
            }}
            #central_content, #left_col, #btn_col {{
                background-color: rgba(0,0,0,0);
            }}
            '''
        )

    # ---------- Scan Handlers (manual scans still use ScanPage) ----------
    def scan_file(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to scan")
        if files:
            dlg = ScanPage(parent=self, scan_type="File", paths=files)
            dlg.exec()

    def scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to scan")
        if folder:
            dlg = ScanPage(parent=self, scan_type="Folder", paths=folder)
            dlg.exec()

    def scan_processes(self):
        dlg = ScanPage(parent=self, scan_type="Processes")
        dlg.exec()

    def view_autoscan_results(self):
        # Button that shows ONLY autoscan logs (not manual scans)
        if self._autoscan_window is None:
            self._autoscan_window = AutoScanResultWindow(parent=self)
        self._autoscan_window.load_logs()
        self._autoscan_window.show()
        self._autoscan_window.raise_()
        self._autoscan_window.activateWindow()

    # ---------- External drive detected callback ----------
    def _on_external_drive_detected(self, mountpoint: str):
        """
        Called (in GUI thread) when ExternalDriveMonitor emits a new mountpoint.
        We open the same ScanPage (Folder scan) UI so you get colored logs and quarantine popups.
        """
        try:
            dlg = ScanPage(parent=self, scan_type="USB Drive", paths=mountpoint)
            dlg.exec()
        except Exception:
            # fallback: start headless autoscan for that mountpoint
            try:
                self._start_autoscan_headless(folders=[mountpoint])
            except Exception:
                pass

    # ---------- Headless AutoScan Starter ----------
    def _start_autoscan_headless(self, folders=None):
        """
        Start AutoScanWorker in background without opening ScanPage dialog.
        Ensures proper thread lifecycle and sets worker stop-event on close.
        """
        # normalize folders
        if folders is None:
            folders_safe = []
        else:
            if isinstance(folders, str):
                folders_safe = [folders]
            else:
                try:
                    folders_safe = list(folders)
                except Exception:
                    folders_safe = []

        # read days from config
        days = 30
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                cfg = json.load(f)
            days = int(cfg.get("autoscan_window_days",
                               cfg.get("auto_scan_days",
                                       cfg.get("auto_scan_interval_days", days))))
        except Exception:
            pass

        # create a QThread (no parent) and worker
        thread = QThread()
        worker = AutoScanWorker(folders_safe, days, parent_dialog=None)
        worker.moveToThread(thread)

        # keep references so GC doesn't kill them
        self._autoscan_threads.append((thread, worker))

        # ---- SAFELY CONNECT SIGNALS ----
        # When worker signals finished -> ask the thread to quit.
        # Do NOT delete worker here.
        worker.finishedSignal.connect(thread.quit)

        # When the thread has fully finished, do the cleanup (GUI/main thread).
        def _on_thread_finished_cleanup():
            try:
                # remove reference from list
                self._autoscan_threads[:] = [t for t in self._autoscan_threads if t[0] is not thread]
            except Exception:
                pass
            try:
                # worker and thread are QObject wrappers; deleteLater() on GUI thread is safe
                try:
                    worker.deleteLater()
                except Exception:
                    pass
            except Exception:
                pass
            try:
                thread.deleteLater()
            except Exception:
                pass

        thread.finished.connect(_on_thread_finished_cleanup)

        # start thread
        thread.started.connect(worker.run)
        thread.start()

    # ---------- Autoscan timer & removable monitor (existing) ----------
    def _init_autoscan_timer_and_monitor(self):
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {
                "auto_scan_enabled": True,
                "auto_scan_interval_minutes": 60,
                "scan_folders_default": []
            }

        # initial delayed launch if enabled
        if cfg.get("auto_scan_enabled", True):
            QTimer.singleShot(800, lambda: self._maybe_launch_autoscan(cfg))

        # timer-based recurring auto-scan
        interval_min = int(cfg.get("auto_scan_interval_minutes", 60))
        if interval_min > 0:
            self._auto_timer = QTimer(self)
            self._auto_timer.setInterval(max(1, interval_min) * 60 * 1000)
            self._auto_timer.timeout.connect(lambda: self._maybe_launch_autoscan(cfg))
            self._auto_timer.start()

    def _maybe_launch_autoscan(self, cfg):
        if cfg.get("auto_scan_enabled", True):
            folders = cfg.get("scan_folders_default", cfg.get("auto_scan_folders", None))
            if folders:
                expanded = []
                home = os.path.expanduser("~")
                for p in folders:
                    if not isinstance(p, str):
                        continue
                    p2 = p.replace("<USER_DESKTOP>", os.path.join(home, "Desktop"))
                    p2 = p2.replace("<USER_DOWNLOADS>", os.path.join(home, "Downloads"))
                    expanded.append(os.path.expanduser(p2))
                folders = expanded
            self._start_autoscan_headless(folders=folders)

    def _launch_autoscan_from_folders(self, folders):
        self._start_autoscan_headless(folders=folders)

    # ---------- cleanup on close ----------
    def closeEvent(self, event):
        # stop external drive monitor (Qt-native)
        try:
            if hasattr(self, "_external_drive_monitor") and self._external_drive_monitor:
                try:
                    self._external_drive_monitor.stop()
                except Exception:
                    pass
        except Exception:
            pass

        # stop any running autoscan threads politely
        try:
            # iterate over copy to avoid modification during loop
            for thread, worker in list(self._autoscan_threads):
                try:
                    # ask worker to stop if it has a stop_event
                    if hasattr(worker, "_stop_event") and worker._stop_event is not None:
                        try:
                            worker._stop_event.set()
                        except Exception:
                            pass
                except Exception:
                    pass

                try:
                    if thread.isRunning():
                        thread.quit()
                        thread.wait(2000)
                except Exception:
                    pass

            # clear list
            self._autoscan_threads.clear()
        except Exception:
            pass

        # stop autoscan result window timer if open
        try:
            if hasattr(self, "_autoscan_window") and self._autoscan_window:
                try:
                    if hasattr(self._autoscan_window, "timer") and self._autoscan_window.timer.isActive():
                        self._autoscan_window.timer.stop()
                except Exception:
                    pass
        except Exception:
            pass

        super().closeEvent(event)
