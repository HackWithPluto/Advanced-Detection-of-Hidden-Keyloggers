import os
import shutil
import customtkinter as ctk
from utils.logger import log_detection  # Ensure logger.py has log_detection

QUARANTINE = os.path.join("database")
QUARANTINE_DIR = os.path.join(QUARANTINE, "quarantine")

if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)


def quarantine_file(file_path, parent=None, ask_user=True, auto_quarantine=False):
    """
    Custom CTk-style modal popup for Quarantine/Delete/Cancel.
    :param file_path: Suspicious file path
    :param parent: CTk parent window
    :param ask_user: Ask user before action
    :param auto_quarantine: Auto move without asking
    :return: quarantined path, 'deleted', or None
    """
    try:
        action_taken = None
        move_file = auto_quarantine
        
        if ask_user and parent:
            # Overlay frame
            overlay = ctk.CTkFrame(parent, width=500, height=180, corner_radius=15, fg_color="#2b2b2b")
            overlay.place(relx=0.5, rely=0.5, anchor="center")

            # Message
            label = ctk.CTkLabel(overlay, text=f"KeyLogger detected:\n{file_path}",
                                 wraplength=460, justify="center", text_color="#ffffff")
            label.pack(pady=(20, 15))

            # Button callbacks
            def do_quarantine():
                nonlocal move_file, action_taken
                move_file = True
                overlay.destroy()

            def do_delete():
                nonlocal action_taken, move_file
                move_file = False
                if os.path.exists(file_path):
                    os.remove(file_path)
                    log_detection(file_path, "File deleted by user")
                    action_taken = "deleted"
                overlay.destroy()

            def do_cancel():
                overlay.destroy()

            # Buttons frame
            btn_frame = ctk.CTkFrame(overlay, fg_color="transparent")
            btn_frame.pack(pady=10)

            ctk.CTkButton(btn_frame, text="Quarantine", width=110, command=do_quarantine).grid(row=0, column=0, padx=10)
            ctk.CTkButton(btn_frame, text="Delete", width=110, fg_color="#FF6B6B", hover_color="#FF3B3B", command=do_delete).grid(row=0, column=1, padx=10)
            ctk.CTkButton(btn_frame, text="Cancel", width=110, fg_color="#aaaaaa", hover_color="#888888", command=do_cancel).grid(row=0, column=2, padx=10)

            # Make modal
            overlay.update()
            overlay.grab_set()
            parent.wait_window(overlay)

            if action_taken == "deleted":
                return action_taken
            if not move_file:
                return None

        if move_file:
            filename = os.path.basename(file_path)
            dest_path = os.path.join(QUARANTINE_DIR, filename)

            count = 1
            while os.path.exists(dest_path):
                name, ext = os.path.splitext(filename)
                dest_path = os.path.join(QUARANTINE_DIR, f"{name}_{count}{ext}")
                count += 1

            shutil.move(file_path, dest_path)
            log_detection(file_path, f"File quarantined to {dest_path}")
            action_taken = dest_path

        return action_taken

    except Exception as e:
        log_detection(file_path, f"Failed to quarantine/delete: {e}")
        return None

