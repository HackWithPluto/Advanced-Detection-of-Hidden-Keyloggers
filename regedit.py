import winreg
import os

# Fake executable paths (they do not exist)
FAKE_ENTRIES = {
    "HKCU": {
        r"Software\Microsoft\Windows\CurrentVersion\Run": {
            "FakeKeyLogger1": r"C:\Users\Public\AppData\Roaming\abc123.exe",
            "SuspiciousEntryA": r"C:\Temp\malicious_run.exe",
        },
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon": {
            "BadShellA": r"C:\Users\Public\AppData\Local\xyz999.exe",
        },
    },
    "HKLM": {
        r"Software\Microsoft\Windows\CurrentVersion\Run": {
            "FakeStartup2": r"C:\ProgramData\test\loader123.exe",
            "TempLoaderX": r"C:\Windows\Temp\weird_app.exe",
        }
    }
}

def add_registry_entry(root, path, name, value):
    try:
        key = winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        print(f"[+] Added: {path} -> {name} = {value}")
    except PermissionError:
        print(f"[!] Permission denied while writing to {path}. Run as Administrator.")
    except FileNotFoundError:
        print(f"[!] Registry path not found: {path}")
    except Exception as e:
        print(f"[!] Error adding entry: {e}")

def main():
    print("=== Adding 5 Fake Suspicious Registry Entries ===\n")

    for hive, paths in FAKE_ENTRIES.items():
        if hive == "HKCU":
            hive_const = winreg.HKEY_CURRENT_USER
        else:
            hive_const = winreg.HKEY_LOCAL_MACHINE

        for path, entries in paths.items():
            for name, value in entries.items():
                add_registry_entry(hive_const, path, name, value)

    print("\n=== Done! Now open your PyQt6 Registry Scanner UI and test detection & removal. ===")

if __name__ == "__main__":
    main()
