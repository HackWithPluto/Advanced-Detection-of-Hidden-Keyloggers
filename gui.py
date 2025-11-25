import sys
import os
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel
from PyQt5.QtGui import QPixmap, QIcon, QFont
from PyQt5.QtCore import Qt
from thread import scan_files_thread, scan_folder_thread, scan_system_processes_thread, stop_event, scan_autoscan_thread, start_removable_monitor, register_autoscan_subscriber, latest_autoscan_results
import json
from scanner.file_scanner import SUPPORTED

# ------------------- Silence Tkinter bgerror -------------------
tk.Tk.report_callback_exception = lambda self, exc, val, tb: None  # ignore errors after destroy

# ---------------- Tkinter Scan Page ----------------
class ScanPage(ctk.CTk):
    def __init__(self, mode=None, return_callback=None):
        super().__init__()
        self.title("Advanced Detection of Hidden Keyloggers")
        self.geometry("900x650")
        self.resizable(False, False)
        self.return_callback = return_callback
        self.text_log = None
        self.progress = None
        self.scan_active = False

        # Ensure threads stop on close
        self.protocol("WM_DELETE_WINDOW", self.close_scan)

        if mode:
            self.show_scanner(mode)
        else:
            self.show_menu()

  
    def show_menu(self):
        self.clear_screen()

        title = ctk.CTkLabel(
            self, text="Advanced Detection of Hidden Keyloggers",
            font=("Arial", 26, "bold"), text_color="#F30808", bg_color="transparent"
        )
        title.pack(pady=30)

        frame_menu = ctk.CTkFrame(self, fg_color="transparent")
        frame_menu.pack(pady=50)

        btn_file = ctk.CTkButton(frame_menu, text="Scan File", width=220, height=50,
                                 corner_radius=20, fg_color="#B3D8FD", text_color="black",
                                 command=lambda: self.show_scanner("File"))
        btn_file.grid(row=0, column=0, padx=20, pady=10)

        btn_folder = ctk.CTkButton(frame_menu, text="Scan Folder", width=220, height=50,
                                   corner_radius=20, fg_color="#C8F7DC", text_color="black",
                                   command=lambda: self.show_scanner("Folder"))
        btn_folder.grid(row=1, column=0, padx=20, pady=10)

        btn_proc = ctk.CTkButton(frame_menu, text="Scan Processes", width=220, height=50,
                                 corner_radius=20, fg_color="#FFF9C5", text_color="black",
                                 command=lambda: self.show_scanner("Processes"))
        btn_proc.grid(row=2, column=0, padx=20, pady=10)

        btn_tw = ctk.CTkButton(frame_menu, text="AutoScan Result", width=220, height=50,
                                corner_radius=20, fg_color="#D6C7FF", text_color="black",
                                command=self.open_autoscan_result)
        btn_tw.grid(row=3, column=0, padx=20, pady=10)

        btn_settings = ctk.CTkButton(frame_menu, text="Settings", width=220, height=50,
                                     corner_radius=20, fg_color="#CCCCCC", text_color="black",
                                     command=self.open_settings)
        btn_settings.grid(row=4, column=0, padx=20, pady=10)

    # Scanner screen
    def show_scanner(self, mode):
        # Select paths
        if mode == "File":
            paths = filedialog.askopenfilenames(
                title="Select files to scan",
                filetypes=[("Supported files", " ".join(f"*{ext}" for ext in SUPPORTED)),
                           ("All files", "*.*")]
            )
            if not paths: return
        elif mode == "Folder":
            paths = filedialog.askdirectory(title="Select folder to scan")
            if not paths: return
        else:
            paths = None

        self.clear_screen()
        self.scan_active = True

        # Title
        title = ctk.CTkLabel(self, text=f"Scanning: {mode}", font=("Arial", 22, "bold"),
                             text_color="#F2F2F2", bg_color="transparent")
        title.pack(pady=(20, 10))

        # Progress bar
        self.progress = ctk.CTkProgressBar(self, width=820, height=22,
                                           fg_color="#eaeaea", progress_color="#4ae2e1", mode="determinate")
        self.progress.set(0.0)
        self.progress.pack(pady=(0, 15))

        # ---------------- Log frame ----------------
        log_frame = ctk.CTkFrame(self, width=860, height=380, corner_radius=16, fg_color="#2b2b2b")
        log_frame.pack(pady=(0, 10))
        log_frame.pack_propagate(0)

        inner_frame = tk.Frame(log_frame, bg="#2b2b2b")
        inner_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.text_log = tk.Text(inner_frame, bg="#1e2024", fg="#ffffff",
                                font=("Consolas", 12), wrap="none", border=0,
                                insertbackground="#fff", selectbackground="#4878d1")
        self.text_log.grid(row=0, column=0, sticky="nsew")

        scrollbar_v = tk.Scrollbar(inner_frame, command=self.text_log.yview)
        scrollbar_v.grid(row=0, column=1, sticky="ns")
        self.text_log.configure(yscrollcommand=scrollbar_v.set)

        scrollbar_h = tk.Scrollbar(inner_frame, command=self.text_log.xview, orient="horizontal")
        scrollbar_h.grid(row=1, column=0, sticky="ew")
        self.text_log.configure(xscrollcommand=scrollbar_h.set)

        inner_frame.grid_rowconfigure(0, weight=1)
        inner_frame.grid_columnconfigure(0, weight=1)

        self.text_log.tag_config("detected", foreground="red")
        self.text_log.tag_config("clean", foreground="green")
        self.text_log.tag_config("complete", foreground="#4ae2e1")
        self.text_log.configure(state="disabled")

        # Bottom buttons frame
        frame_bottom = ctk.CTkFrame(self, fg_color="transparent")
        frame_bottom.pack(fill="x", pady=5)

        btn_back = ctk.CTkButton(frame_bottom, text="← Back", corner_radius=20,
                                 fg_color="#A7E0FF", text_color="black", command=self.close_scan)
        btn_back.pack(side="left", padx=10)

        btn_exit = ctk.CTkButton(frame_bottom, text="❌ Exit", corner_radius=20,
                                 fg_color="#FF6B6B", text_color="white", command=self.close_scan)
        btn_exit.pack(side="left", padx=10)

        btn_clean = ctk.CTkButton(frame_bottom, text="Clean", corner_radius=20,
                                  fg_color="#FFCFCF", text_color="black", command=self.clear_results)
        btn_clean.pack(side="right", padx=10)

        btn_stop = ctk.CTkButton(frame_bottom, text="Stop Scan", corner_radius=20,
                                 fg_color="#FFB266", text_color="black", command=self.stop_scan)
        btn_stop.pack(side="right", padx=10)

        # Start scanning
        self.after(100, lambda: self.start_scan_live(mode, paths))

    # Live scan
    def start_scan_live(self, mode, paths):
        stop_event.clear()

        def log_callback(file_path, status):
            if not self.scan_active:  # skip updates if closed
                return
            try:
                self.text_log.configure(state="normal")
                tag = "detected" if status == "suspicious" else "clean"
                self.text_log.insert("end", f"{file_path} → {'KEYLOGGER DETECTED' if status=='suspicious' else 'CLEAN FILE'}\n", tag)
                self.text_log.see("end")
                self.text_log.configure(state="disabled")
            except tk.TclError:
                pass

        def complete_callback():
            if not self.scan_active:
                return
            try:
                self.text_log.configure(state="normal")
                self.text_log.insert("end", "--- Scan Completed ---\n", "complete")
                self.text_log.configure(state="disabled")
                if self.progress:
                    self.progress.set(100)
            except tk.TclError:
                pass

        if mode == "File":
            scan_files_thread(self.text_log, paths, self.progress, callback=log_callback, on_complete=complete_callback)
        elif mode == "Folder":
            scan_folder_thread(self.text_log, paths, self.progress, callback=log_callback, on_complete=complete_callback)
        elif mode == "Processes":
            scan_system_processes_thread(self.text_log, self.progress, callback=log_callback, on_complete=complete_callback)
        elif mode == "AutoScan":
            scan_autoscan_thread(None, None, callback=None, on_complete=None)
        elif isinstance(mode, dict) and mode.get("AutoScanFolders"):
            scan_autoscan_thread(None, None, folders=mode["AutoScanFolders"], callback=None, on_complete=None)

    # Utilities
    def clear_results(self):
        try:
            if self.text_log:
                self.text_log.configure(state="normal")
                self.text_log.delete(1.0, tk.END)
                self.text_log.configure(state="disabled")
            if self.progress:
                self.progress.set(0.0)
        except tk.TclError:
            pass

    def stop_scan(self):
        stop_event.set()
        self.append_log("--- Scan cancelled by user ---")

    def append_log(self, text):
        try:
            if self.text_log:
                self.text_log.configure(state="normal")
                self.text_log.insert("end", text + "\n")
                self.text_log.see("end")
                self.text_log.configure(state="disabled")
        except tk.TclError:
            pass

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    def close_scan(self):
        self.scan_active = False
        stop_event.set()
        try:
            self.destroy()
        except:
            pass
        if self.return_callback:
            self.return_callback()

    def _load_config(self):
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {
                "autoscan_window_days": 30,
                "auto_scan_interval_minutes": 60,
                "scan_folders_default": ["<USER_DESKTOP>", "<USER_DOWNLOADS>"],
                "log_path": "database/logs/scan_logs.txt",
                "quarantine_path": "database/quarantine",
                "debug": False,
                "auto_scan_enabled": True
            }

    def _save_config(self, cfg):
        try:
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

    def open_settings(self):
        cfg = self._load_config()
        win = ctk.CTkToplevel(self)
        win.title("Settings")
        win.geometry("420x320")

        ctk.CTkLabel(win, text="Auto Scan Window (days)").pack(pady=(12, 4))
        ent_days = ctk.CTkEntry(win)
        ent_days.insert(0, str(cfg.get("autoscan_window_days", 30)))
        ent_days.pack(pady=4)

        ctk.CTkLabel(win, text="Auto-scan interval (minutes)").pack(pady=(12, 4))
        ent_interval = ctk.CTkEntry(win)
        ent_interval.insert(0, str(cfg.get("auto_scan_interval_minutes", 60)))
        ent_interval.pack(pady=4)

        auto_var = tk.IntVar(value=1 if cfg.get("auto_scan_enabled", True) else 0)
        chk_auto = ctk.CTkCheckBox(win, text="Enable auto-scan", variable=auto_var)
        chk_auto.pack(pady=8)

        folder_frame = ctk.CTkFrame(win)
        folder_frame.pack(pady=10)
        ctk.CTkLabel(folder_frame, text="Scan Folders:").pack()
        def has_token(lst, tok):
            return any(tok in lst)
        var_desktop = tk.IntVar(value=1 if has_token(cfg.get("scan_folders_default", []), "<USER_DESKTOP>") else 0)
        var_downloads = tk.IntVar(value=1 if has_token(cfg.get("scan_folders_default", []), "<USER_DOWNLOADS>") else 0)
        ctk.CTkCheckBox(folder_frame, text="Desktop", variable=var_desktop).pack(anchor="w", padx=12)
        ctk.CTkCheckBox(folder_frame, text="Downloads", variable=var_downloads).pack(anchor="w", padx=12)

        def save():
            try:
                days = int(ent_days.get())
                interval = int(ent_interval.get())
            except:
                days = cfg.get("autoscan_window_days", 30)
                interval = cfg.get("auto_scan_interval_minutes", 60)
            folders = []
            if var_desktop.get() == 1:
                folders.append("<USER_DESKTOP>")
            if var_downloads.get() == 1:
                folders.append("<USER_DOWNLOADS>")
            new_cfg = {
                **cfg,
                "autoscan_window_days": days,
                "auto_scan_interval_minutes": interval,
                "scan_folders_default": folders,
                "auto_scan_enabled": auto_var.get() == 1
            }
            self._save_config(new_cfg)
            win.destroy()

        ctk.CTkButton(win, text="Save", command=save).pack(pady=14)

    def open_autoscan_result(self):
        self._autoscan_panel = AutoScanResultPanel(self)
        self._autoscan_panel.refresh_results(latest_autoscan_results)



# ---------------- Resource path for PyInstaller ----------------
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


# ---------------- PyQt5 Landing Page ----------------
class LandingPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Detection of Hidden Keyloggers")
        self.setGeometry(200, 100, 1000, 650)
        self._init_autoscan()

        # Background label
        self.bg_label = QLabel(self)
        self.bg_label.setGeometry(0, 0, self.width(), self.height())
        self.bg_label.lower()
        self.update_background()

        # Layout
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(130, 140, 0, 0)
        self.layout.setSpacing(20)

        # Heading
        heading = QLabel("KeyDefender")
        heading.setFont(QFont("Arial", 18, QFont.Bold))
        heading.setStyleSheet("color: #00E5FF;")
        heading.setAlignment(Qt.AlignLeft)
        heading.setContentsMargins(15, 0, 0, 0)
        self.layout.addWidget(heading)
        self.layout.addSpacing(15)

        # Button style
        btn_style = """
        QPushButton {
            background-color: rgba(0,0,0,120);
            color: #00E5FF;
            border: 2px solid #00E5FF;
            border-radius: 15px;
            font-size: 16px;
            font-weight: bold;
            padding: 8px 14px;
            min-width: 180px;
            max-width: 180px;
        }
        QPushButton:hover {
            background-color: rgba(0,229,255,60);
            border: 2px solid #FFFFFF;
            color: white;
        }
        QPushButton:pressed {
            background-color: rgba(0,229,255,120);
            border: 2px solid #00B8D4;
            color: black;
        }
        """

        # Buttons
        scan_file_btn = QPushButton("Scan File")
        scan_file_btn.setStyleSheet(btn_style)
        scan_file_btn.clicked.connect(lambda: self.launch_scan_page("File"))

        scan_folder_btn = QPushButton("Scan Folder")
        scan_folder_btn.setStyleSheet(btn_style)
        scan_folder_btn.clicked.connect(lambda: self.launch_scan_page("Folder"))

        system_scan_btn = QPushButton("System Scan")
        system_scan_btn.setStyleSheet(btn_style)
        system_scan_btn.clicked.connect(lambda: self.launch_scan_page("Processes"))

        exit_btn = QPushButton("Exit")
        exit_btn.setStyleSheet(btn_style)
        exit_btn.setIcon(QIcon.fromTheme("application-exit"))
        exit_btn.clicked.connect(self.close)

        for btn in [scan_file_btn, scan_folder_btn, system_scan_btn, exit_btn]:
            self.layout.addWidget(btn)
        tw_btn = QPushButton("AutoScan Result")
        tw_btn.setStyleSheet(btn_style)
        tw_btn.clicked.connect(self.launch_autoscan_result)
        self.layout.addWidget(tw_btn)

        settings_btn = QPushButton("Settings")
        settings_btn.setStyleSheet(btn_style)
        settings_btn.clicked.connect(self.launch_settings)
        self.layout.addWidget(settings_btn)

        self.layout.addStretch()
        self.setLayout(self.layout)

    # ---------------- Update Background ----------------
    def update_background(self):
        bg_path = resource_path("database/images/background.png")
        if os.path.exists(bg_path):
            pixmap = QPixmap(bg_path)
            self.bg_label.setPixmap(pixmap.scaled(
                self.size(),
                Qt.KeepAspectRatioByExpanding,
                Qt.SmoothTransformation
            ))

    # Resize background dynamically
    def resizeEvent(self, event):
        self.update_background()
        super().resizeEvent(event)

    # Launch Tkinter Scan Page
    def launch_scan_page(self, mode):
        self.hide()
        app_tk = ScanPage(mode, return_callback=self.show)

        # Proper exit handling
        def on_exit():
            stop_event.set()
            try:
                app_tk.destroy()
            except:
                pass
            self.show()

        app_tk.protocol("WM_DELETE_WINDOW", on_exit)
        app_tk.mainloop()

    def launch_autoscan_result(self):
        panel = AutoScanResultPanel(parent=None)
        panel.refresh_results(latest_autoscan_results)

    def launch_settings(self):
        self.hide()
        app_tk = ScanPage("Settings", return_callback=self.show)
        app_tk.mainloop()

    def _read_cfg(self):
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"auto_scan_enabled": True, "auto_scan_interval_minutes": 60}

    def _init_autoscan(self):
        from PyQt5.QtCore import QTimer
        cfg = self._read_cfg()
        if cfg.get("auto_scan_enabled", True):
            t = QTimer(self)
            t.setSingleShot(True)
            t.timeout.connect(lambda: scan_autoscan_thread(None, None))
            t.start(500)
        interval_min = int(cfg.get("auto_scan_interval_minutes", 60))
        if interval_min > 0:
            self._auto_timer = QTimer(self)
            self._auto_timer.setInterval(interval_min * 60 * 1000)
            self._auto_timer.timeout.connect(lambda: scan_autoscan_thread(None, None))
            self._auto_timer.start()
        start_removable_monitor(lambda mp: scan_autoscan_thread(None, None, folders=[mp]))

        def subscriber(results):
            try:
                if getattr(self, "_autoscan_panel", None):
                    self._autoscan_panel.refresh_results(results)
            except Exception:
                pass
        register_autoscan_subscriber(subscriber)

class AutoScanResultPanel(ctk.CTkToplevel):
    def __init__(self, parent=None):
        super().__init__(parent) if parent else ctk.CTkToplevel()
        self.title("AutoScan Results")
        self.geometry("900x650")
        self.resizable(False, False)
        self.text_log = None
        self.progress = None
        self._build()

    def _build(self):
        title = ctk.CTkLabel(self, text="AutoScan Results", font=("Arial", 22, "bold"),
                             text_color="#F2F2F2", bg_color="transparent")
        title.pack(pady=(20, 10))

        self.text_log = tk.Text(self, bg="#1e2024", fg="#ffffff",
                                font=("Consolas", 12), wrap="none", border=0,
                                insertbackground="#fff", selectbackground="#4878d1")
        self.text_log.pack(fill="both", expand=True, padx=10, pady=10)
        self.text_log.tag_config("detected", foreground="red")
        self.text_log.tag_config("clean", foreground="green")
        self.text_log.tag_config("complete", foreground="#4ae2e1")

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", pady=5)

        ctk.CTkButton(btn_frame, text="Delete", command=self._delete_selected).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Quarantine", command=self._quarantine_selected).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Mark Normal", command=self._mark_normal_selected).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Clean", command=self._clean).pack(side="right", padx=6)

    def refresh_results(self, results):
        try:
            self.text_log.configure(state="normal")
            self.text_log.delete(1.0, tk.END)
            if results:
                for r in results:
                    fp = r.get("file")
                    status = r.get("status")
                    tag = "detected" if status == "suspicious" else "clean"
                    self.text_log.insert("end", f"{fp} → {'KEYLOGGER DETECTED' if status=='suspicious' else 'CLEAN FILE'}\n", tag)
            self.text_log.insert("end", "--- Scan Completed ---\n", "complete")
            self.text_log.configure(state="disabled")
        except tk.TclError:
            pass

    def _selected_filepath(self):
        try:
            idx = self.text_log.index("insert linestart")
            line = self.text_log.get(idx, f"{idx} lineend")
            fp = line.split(" → ")[0].strip()
            return fp
        except Exception:
            return None

    def _delete_selected(self):
        fp = self._selected_filepath()
        if fp and os.path.exists(fp):
            try:
                os.remove(fp)
                from utils.logger import log_detection
                log_detection(fp, "File deleted by user")
            except Exception:
                pass

    def _quarantine_selected(self):
        from utils.quarantine import quarantine_file
        fp = self._selected_filepath()
        if fp and os.path.exists(fp):
            quarantine_file(fp, parent=self, ask_user=True)

    def _mark_normal_selected(self):
        from utils.logger import log_detection
        fp = self._selected_filepath()
        if fp:
            log_detection(fp, "Marked normal by user")

    def _clean(self):
        try:
            self.text_log.configure(state="normal")
            self.text_log.delete(1.0, tk.END)
            self.text_log.configure(state="disabled")
        except tk.TclError:
            pass
