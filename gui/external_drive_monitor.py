# gui/external_drive_monitor.py
"""
ExternalDriveMonitor (Qt-native).

- Runs its monitoring loop inside a QThread.
- Emits `driveDetected(str)` when a new mountpoint appears.
- Emits `heartbeat()` every poll_interval seconds so UI can refresh logs/live info.
- Uses psutil.disk_partitions(all=False) if psutil is installed.
- Safe fallback when psutil is missing (monitor still runs and emits heartbeat).
"""

import time
import platform
import os

from PyQt6.QtCore import QObject, QThread, pyqtSignal

try:
    import psutil
except Exception:
    psutil = None


class ExternalDriveMonitor(QObject):
    """
    Monitors mounted partitions and emits Qt signals:
      - driveDetected(str) : emitted with normalized mountpoint when a new drive is detected
      - heartbeat()         : emitted every poll_interval seconds (use to refresh logs/UI)
    Runs loop inside a QThread so it's fully Qt-friendly.
    """

    driveDetected = pyqtSignal(str)  # emitted with mountpoint string
    heartbeat = pyqtSignal()         # emitted every poll_interval seconds

    def __init__(self, poll_interval: float = 1.0, parent: QObject | None = None):
        """
        :param poll_interval: seconds between checks and heartbeats (default 1.0)
        """
        super().__init__(parent)
        self.poll_interval = max(0.5, float(poll_interval))
        self._running = False
        self._known_mounts = set()
        self._thread: QThread | None = None

        # init known mounts
        self._init_known_mounts()

    def _init_known_mounts(self):
        try:
            if psutil:
                self._known_mounts = set(p.mountpoint for p in psutil.disk_partitions(all=False))
            else:
                # fallback: include root (POSIX) or existing drive letters (Windows)
                mounts = set()
                if platform.system().lower().startswith("win"):
                    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                        path = f"{ch}:/"
                        if os.path.exists(path):
                            mounts.add(path)
                else:
                    mounts.add("/")
                self._known_mounts = mounts
        except Exception:
            self._known_mounts = set()

    def start(self):
        """Start the monitor inside a QThread. Safe to call multiple times."""
        if self._thread and self._thread.isRunning():
            return

        # create a thread, move this object into it, and start the loop when thread starts
        self._thread = QThread()
        self.moveToThread(self._thread)
        # connect the thread start to the monitor loop method (runs inside the QThread)
        self._thread.started.connect(self._monitor_loop)
        self._running = True
        self._thread.start()

    def stop(self):
        """Stop monitoring and quit the thread cleanly."""
        try:
            self._running = False
            if self._thread:
                # if thread is running, ask it to quit and wait briefly
                if self._thread.isRunning():
                    self._thread.quit()
                    self._thread.wait(800)
                self._thread = None
        except Exception:
            pass

    def _list_current_mounts_fallback(self):
        """Return a set of mountpoints using a simple fallback (no psutil)."""
        mounts = set()
        try:
            if platform.system().lower().startswith("win"):
                for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    path = f"{ch}:/"
                    if os.path.exists(path):
                        mounts.add(path)
            else:
                mounts.add("/")
        except Exception:
            pass
        return mounts

    def _monitor_loop(self):
        """
        This runs inside the QThread. Emit driveDetected when a new mountpoint appears.
        Also emit heartbeat every poll_interval seconds so UI can refresh logs live.
        """
        # refresh known set on start
        self._init_known_mounts()

        while self._running:
            try:
                if psutil:
                    current = set(p.mountpoint for p in psutil.disk_partitions(all=False))
                else:
                    current = self._list_current_mounts_fallback()

                added = sorted([mp for mp in current if mp not in self._known_mounts])

                # emit each added mountpoint (queued to GUI thread)
                for mp in added:
                    try:
                        # basic normalization on Windows (ensure trailing slash style)
                        mp_norm = os.path.abspath(mp)
                        # make Windows mountpoints consistent like 'C:/' -> 'C:\\' on Windows
                        if platform.system().lower().startswith("win"):
                            # os.path.abspath keeps style; replace backslashes for consistency
                            mp_norm = mp_norm.replace("\\", "/")
                            # ensure trailing slash
                            if not mp_norm.endswith("/"):
                                mp_norm = mp_norm + "/"
                        self.driveDetected.emit(mp_norm)
                    except Exception:
                        pass

                # update known
                self._known_mounts = current

                # emit heartbeat so UI can refresh logs/live display
                try:
                    self.heartbeat.emit()
                except Exception:
                    pass

            except Exception:
                # ignore transient errors so monitor keeps running
                pass

            # sleep in small increments so stop is responsive
            step = 0.1
            slept = 0.0
            while slept < self.poll_interval and self._running:
                time.sleep(step)
                slept += step



