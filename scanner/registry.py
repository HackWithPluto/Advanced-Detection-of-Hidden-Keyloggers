# scanner/registry.py
"""
Registry Scanner dialog (PyQt6)

Provides:
- RegistryScannerDialog: a modeless/modal dialog showing suspicious startup registry values.
- Embedded scan_registry() that checks Run / RunOnce / Winlogon in HKCU and HKLM for string values
  pointing into AppData/Temp/ProgramData and ending with .exe (the same logic your scanner uses).
- A Run Scan button, Save Report As..., Remove Selected (shown dynamically), and Exit button at bottom-right.
- Deleting removes a registry *value* (asks for confirmation). Requires Administrator privileges for HKLM.
"""

from PyQt6.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLabel, QFileDialog, QMessageBox, QWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import json
import os
import sys
import winreg

# --- Embedded scan function (matches your scanner heuristic) ---
STARTUP_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
]

# ROOTS includes tuple of (winreg constant, readable hive name)
ROOTS = [(winreg.HKEY_CURRENT_USER, 'HKCU'), (winreg.HKEY_LOCAL_MACHINE, 'HKLM')]


def scan_registry():
    """
    Return list of dicts:
      {
        'hive': 'HKCU' or 'HKLM',
        'root_const': winreg constant (HKEY_*),
        'registry_path': <path string>,
        'value_name': <value name>,
        'value_data': <value data string>
      }
    Only includes entries where the value is a REG_SZ string containing 'appdata'/'temp'/'programdata'
    and ending with '.exe' (heuristic used to detect suspicious startup entries).
    """
    suspicious = []

    for root_const, hive_name in ROOTS:
        for path in STARTUP_KEYS:
            try:
                key = winreg.OpenKey(root_const, path, 0, winreg.KEY_READ)
            except FileNotFoundError:
                continue
            i = 0
            while True:
                try:
                    name, value, vtype = winreg.EnumValue(key, i)
                except OSError:
                    break
                # only process string values
                if vtype == winreg.REG_SZ and isinstance(value, str):
                    exe = value.lower()
                    if ("appdata" in exe or "temp" in exe or "programdata" in exe) and exe.endswith(".exe"):
                        suspicious.append({
                            'hive': hive_name,
                            'root_const': root_const,
                            'registry_path': path,
                            'value_name': name,
                            'value_data': value
                        })
                i += 1
    return suspicious


# --- QThread runner for scan ---
class ScanThread(QThread):
    finished_signal = pyqtSignal(list, str)  # results, message

    def run(self):
        try:
            results = scan_registry()
            self.finished_signal.emit(results, "Scan completed")
        except Exception as e:
            self.finished_signal.emit([], f"Scan failed: {e}")


# --- Registry Scanner Dialog ---
class RegistryScannerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Registry Startup Scanner")
        self.resize(1000, 650)
        self.results = []
        self._build_ui()

    def _build_ui(self):
        main_layout = QVBoxLayout(self)

        # Top Buttons row
        top_btn_layout = QHBoxLayout()
        self.run_btn = QPushButton("Run Scan")
        self.run_btn.clicked.connect(self.on_run_scan)
        self.save_btn = QPushButton("Save Report As...")
        self.save_btn.clicked.connect(self.on_save_report)
        self.remove_btn = QPushButton("Remove Selected")
        self.remove_btn.clicked.connect(self.on_remove_selected)
        # start hidden/disabled until a removable item is selected
        self.remove_btn.setEnabled(False)
        self.remove_btn.setVisible(False)

        top_btn_layout.addWidget(self.run_btn)
        top_btn_layout.addWidget(self.save_btn)
        top_btn_layout.addWidget(self.remove_btn)
        top_btn_layout.addStretch()
        main_layout.addLayout(top_btn_layout)

        # Results tree (above)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Hive", "Registry Path", "Value Name", "Value Data"])
        self.tree.itemSelectionChanged.connect(self.on_selection_changed)
        main_layout.addWidget(self.tree, stretch=65)

        # Details area below the results
        self.details_label = QLabel("Select an entry to see details")
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        main_layout.addWidget(self.details_label)
        main_layout.addWidget(self.details_text, stretch=35)

        # Status
        self.status = QLabel("")
        main_layout.addWidget(self.status)

        # Bottom-right Exit button
        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()
        self.exit_btn = QPushButton("Exit")
        self.exit_btn.clicked.connect(self.close)
        bottom_layout.addWidget(self.exit_btn)
        main_layout.addLayout(bottom_layout)

    def set_status(self, text, error=False):
        self.status.setText(text)
        if error:
            self.status.setStyleSheet("color: red;")
        else:
            self.status.setStyleSheet("")

    def on_run_scan(self):
        self.run_btn.setEnabled(False)
        self.set_status("Scanning...")
        self.thread = ScanThread()
        self.thread.finished_signal.connect(self.on_scan_finished)
        self.thread.start()

    def on_scan_finished(self, results, message):
        self.run_btn.setEnabled(True)
        self.results = results
        self.populate_tree()
        self.set_status(message)

    def populate_tree(self):
        self.tree.clear()
        for it in self.results:
            hive = it.get('hive')
            path = it.get('registry_path')
            name = it.get('value_name')
            value = it.get('value_data')
            # put hive in column 0, path 1, name 2, data 3
            item = QTreeWidgetItem(self.tree, [hive, path, name, value])
            # store raw dict for later
            item.setData(0, Qt.ItemDataRole.UserRole, it)
        self.tree.expandAll()
        # hide remove button initially
        self.remove_btn.setVisible(False)
        self.remove_btn.setEnabled(False)

    def on_selection_changed(self):
        sel = self.tree.selectedItems()
        if not sel:
            self.details_text.clear()
            # hide remove button
            self.remove_btn.setVisible(False)
            self.remove_btn.setEnabled(False)
            return
        item = sel[0]
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            self.details_text.clear()
            self.remove_btn.setVisible(False)
            self.remove_btn.setEnabled(False)
            return
        pretty = {
            'hive': data.get('hive'),
            'registry_path': data.get('registry_path'),
            'value_name': data.get('value_name'),
            'value_data': data.get('value_data')
        }
        self.details_text.setPlainText(json.dumps(pretty, indent=2, ensure_ascii=False))

        # show remove button dynamically for selected detected registry entries
        # we only allow deleting named values (not keys). All scanned items are value entries.
        self.remove_btn.setVisible(True)
        self.remove_btn.setEnabled(True)

    def on_save_report(self):
        if not self.results:
            QMessageBox.information(self, "Save Report", "No results to save. Run a scan first.")
            return
        fn, _ = QFileDialog.getSaveFileName(self, "Save report as", os.path.expanduser("~"), "JSON files (*.json);;All files (*)")
        if not fn:
            return
        try:
            with open(fn, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Save Report", f"Saved report to {fn}")
        except Exception as e:
            QMessageBox.warning(self, "Save Report", f"Failed to save: {e}")

    def on_remove_selected(self):
        sel = self.tree.selectedItems()
        if not sel:
            return
        item = sel[0]
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return

        hive = data.get('hive')
        root_const = data.get('root_const')
        reg_path = data.get('registry_path')
        value_name = data.get('value_name')

        msg = (f"Are you sure you want to DELETE the registry value?\n\n"
               f"Hive: {hive}\nPath: {reg_path}\nValue name: {value_name}\n\n"
               "This operation cannot be undone. Consider exporting the key first.")
        reply = QMessageBox.question(self, "Confirm Delete", msg, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return

        # attempt deletion
        try:
            # open key with write access and delete the named value
            key = winreg.OpenKey(root_const, reg_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value_name)
            try:
                key.Close()
            except Exception:
                pass
            QMessageBox.information(self, "Remove", f"Deleted value '{value_name}' from {hive}\\{reg_path}")
            # refresh scan automatically to update list
            self.on_run_scan()
        except PermissionError:
            QMessageBox.warning(self, "Remove", "Permission denied. Try running the UI as Administrator.")
        except FileNotFoundError:
            QMessageBox.warning(self, "Remove", "The registry value or key was not found (it may have been removed already).")
        except Exception as e:
            QMessageBox.warning(self, "Remove", f"Failed to delete registry value: {e}")


# Allow running this file directly for quick testing/debugging
if __name__ == '__main__':
    if os.name != 'nt':
        print('This UI is for Windows only.')
        sys.exit(1)

    app = QApplication(sys.argv)
    dlg = RegistryScannerDialog()
    dlg.show()
    sys.exit(app.exec())
