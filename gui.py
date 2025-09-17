import os
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
from thread import scan_files_thread, scan_folder_thread, scan_system_processes_thread, stop_event
from scanner.file_scanner import SUPPORTED

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


class AntiKeyloggerScanner(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Anti-Keylogger")
        self.geometry("900x650")
        self.resizable(False, False)
        self.configure(bg="#f6f7fb")

        # Title
        self.title_label = ctk.CTkLabel(
            self, text="ANTI-KEYLOGGER",
            font=("Arial", 22, "bold"),
            text_color="#F30808"
        )
        self.title_label.pack(pady=(20, 10), anchor="center")

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(0, 20))

        btn_cfg = [
            ("Scan File", "#B3D8FD"),
            ("Scan Folder", "#C8F7DC"),
            ("Scan Processes", "#FFF9C5"),
            ("Clear Results", "#FFCFCF"),
            ("Stop Scan", "#FFB266"),
        ]
        self.buttons = []
        for idx, (label, color) in enumerate(btn_cfg):
            btn = ctk.CTkButton(
                btn_frame, text=label, corner_radius=15, width=140,
                fg_color=color, text_color="#223555",
                hover_color="#eaf0fa", border_color="#dddddd", border_width=1,
                command=lambda n=label: self.handle_button(n)
            )
            btn.grid(row=0, column=idx, padx=8)
            self.buttons.append(btn)

        # Progress Bar
        self.progress = ctk.CTkProgressBar(
            self, width=820, height=22,
            fg_color="#eaeaea", progress_color="#4ae2e1",
            mode="determinate"
        )
        self.progress.set(0.0)
        self.progress.pack(pady=(0, 15))

        # Terminal Log Frame
        log_frame = ctk.CTkFrame(self, width=860, height=350, corner_radius=16, fg_color="#ffffff")
        log_frame.pack(pady=(0, 10))
        log_frame.pack_propagate(0)

        # Scrollable Log
        self.text_log = tk.Text(
            log_frame, bg="#1e2024", fg="#ffffff",
            font=("Consolas", 12), wrap="none", border=0,
            insertbackground="#fff", selectbackground="#4878d1"
        )
        self.text_log.pack(side="left", fill="both", expand=True)
        self.scrollbar = ctk.CTkScrollbar(log_frame, command=self.text_log.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.text_log.configure(yscrollcommand=self.scrollbar.set, state="disabled")

    def handle_button(self, label):
        # Reset progress for new scan
        if label in ["Scan File", "Scan Folder", "Scan Processes"]:
            self.progress.set(0.0)

        if label == "Scan File":
            stop_event.clear()
            file_paths = filedialog.askopenfilenames(
                title="Select files to scan",
                filetypes=[("Supported files", " ".join(f"*{ext}" for ext in SUPPORTED)),
                           ("All files", "*.*")]
            )
            if file_paths:
                scan_files_thread(self.text_log, file_paths, self.progress)

        elif label == "Scan Folder":
            stop_event.clear()
            folder_path = filedialog.askdirectory(title="Select folder to scan")
            if folder_path:
                scan_folder_thread(self.text_log, folder_path, self.progress)

        elif label == "Scan Processes":
            stop_event.clear()
            scan_system_processes_thread(self.text_log, self.progress)

        elif label == "Clear Results":
            self.text_log.configure(state="normal")
            self.text_log.delete(1.0, tk.END)
            self.text_log.configure(state="disabled")
            self.progress.set(0.0)

        elif label == "Stop Scan":
            stop_event.set()
            self.append_log("--- Scan cancelled by user ---")

    def append_log(self, text):
        self.text_log.configure(state="normal")
        self.text_log.insert("end", text + "\n")
        self.text_log.see("end")
        self.text_log.configure(state="disabled")
