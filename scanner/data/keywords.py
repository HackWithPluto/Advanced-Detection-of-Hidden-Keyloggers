import re
import PyPDF2
# -----------------------------
# Suspicious keywords and patterns
# -----------------------------
KEYWORDS = {
    "py": [
        # 🔹 Imports & Libraries
        "pynput", "keyboard", "pynput.keyboard", "pynput.mouse", "pynput.mouse.Listener",
        "Listener", "KeyLogger", "pynput.keyboard.Listener", "pynput.mouse.Listener",
        "getpass", "win32api", "win32console", "win32gui", "win32con", "win32event",
        "win32clipboard", "pyHook", "pyxhook", "ctypes", "ctypes.windll", "ctypes.WinDLL",
        "pyautogui", "socket", "requests", "smtplib", "ftplib", "paramiko",
        "telegram", "discord", "http.client", "urllib.request", "urllib3", "subprocess",
        "os.system", "platform", "uuid", "psutil", "shutil", "base64", "cryptography",
        "Crypto.Cipher", "fernet", "hashlib", "marshal", "zlib", "lzma", "bz2", "pickle",

        # 🔹 Keylogging Functions
        "GetAsyncKeyState", "GetForegroundWindow", "GetWindowText", "GetKeyboardState",
        "ToUnicode", "VkKeyScan", "GetKeyState", "MapVirtualKey", "PeekMessage",
        "SendInput", "SetWindowsHookEx", "UnhookWindowsHookEx", "CallNextHookEx",
        "GetMessage", "DispatchMessage", "TranslateMessage", "WH_KEYBOARD_LL",
        "LowLevelKeyboardProc", "HookProc", "CallNextHookEx",

        # 🔹 Persistence & Startup
        "RunOnce", "RunServices", "RunServicesOnce", "StartupFolder", "HKCU",
        "HKLM", "Registry", "reg add", "schtasks", "Task Scheduler", "services.msc",
        "persistence", "startup", "autorun.inf", "shell:startup",

        # 🔹 File Handling / Logging
        "open(", "write(", "append(", "log.txt", "keylog.txt", "keystrokes.txt",
        "save_keys", "record_keys", "f.write", "with open", "keylog", "keystrokes",
        "logging.basicConfig", "logging.FileHandler", "logging.StreamHandler",
        "rotate_log", "rotatingfilehandler", "tempfile", "os.getenv('APPDATA')",

        # 🔹 Exfiltration / Network
        "sendmail", "SMTP", "smtplib.SMTP", "send_keys", "exfiltrate",
        "socket.send", "socket.connect", "socket.recv", "socket.sendall",
        "POST /", "GET /", "http://", "https://", "ftp://", "ssh ",
        "scp ", "wget ", "curl ", "requests.post", "requests.get",
        "upload", "exfil", "sendto", "webhook", "telegram.Bot",

        # 🔹 Encryption / Obfuscation
        "encode(", "decode(", "base64.b64encode", "base64.b64decode",
        "xor", "AES", "DES", "RSA", "fernet.encrypt", "fernet.decrypt",
        "exec(", "eval(", "compile(", "marshal.loads", "zlib.decompress",
        "execfile", "runpy.run_module", "obfuscate", "pack_keys",

        # 🔹 Misc / Indicators
        "hide_window", "Stealth", "invisible", "cam_capture", "screenshot",
        "ImageGrab", "pyscreenshot", "cv2.VideoCapture", "mic_record",
        "sounddevice.rec", "pyAudio", "camera", "microphone", "record_audio",
        "screencap", "clipboard", "GetClipboardData", "SetClipboardData"
    ],

    "KEYWORDS" : {
    "vbs": [
        # --- Objects / Automation ---
        "CreateObject", "WScript.Shell", "WScript.Sleep", "WScript.Echo",
        "FileSystemObject", "ShellExecute", "ActiveXObject", "GetObject",
        "Set obj", "Dim", "MsgBox",
        
        # --- File Handling ---
        "OpenTextFile", "WriteLine", "AppendText", "ReadLine", "DeleteFile",
        "CopyFile", "MoveFile", "CreateTextFile", "GetFile", "GetFolder",
        
        # --- Network / Downloaders ---
        "XMLHTTP", "WinHttp.WinHttpRequest", "MSXML2.XMLHTTP", "ADODB.Stream",
        "DownloadFile", "SaveToFile", "responseBody", "send",
        
        # --- Persistence ---
        "RegWrite", "RegRead", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "RunOnce", "Schedule.Service",
        
        # --- Obfuscation ---
        "Chr(", "ChrW(", "Replace(", "Split(", "Join(", "Xor", "HexToStr",
        
        # --- Dangerous Commands ---
        "cmd.exe", "powershell", "cscript.exe", "wscript.exe", "shutdown",
        "taskkill", "whoami", "ping", "ipconfig", "net user"
    ],
    
    "js": [
        # --- WSH JavaScript ---
        "ActiveXObject", "WScript.Shell", "WScript.Sleep", "WScript.Echo",
        "new ActiveXObject", "FileSystemObject", "Scripting.Dictionary",
        
        # --- File / Registry ---
        "OpenTextFile", "WriteLine", "DeleteFile", "MoveFile", "RegWrite", "RegRead",
        
        # --- Network ---
        "MSXML2.XMLHTTP", "WinHttp.WinHttpRequest", "ADODB.Stream",
        "DownloadFile", "SaveToFile", "responseBody", "send",
        
        # --- Obfuscation ---
        "eval(", "Function(", "String.fromCharCode", "unescape(", "escape(",
        "atob(", "btoa(", "Base64", "Xor",
        
        # --- OS Abuse ---
        "cmd.exe", "powershell", "cscript.exe", "wscript.exe",
        "net user", "whoami", "taskkill", "ping", "ipconfig"
    ],
    
    "ps1": [
        # --- Cmdlets / Execution ---
        "Invoke-Expression", "IEX", "Invoke-WebRequest", "New-Object",
        "Add-Type", "Start-Process", "Invoke-Command", "DownloadString",
        
        # --- Obfuscation ---
        "-EncodedCommand", "-enc", "-nop", "-w hidden", "FromBase64String",
        "StringBuilder", "Split(", "Join(", "Replace(", "iex(",
        
        # --- File / Registry ---
        "Get-Content", "Set-Content", "Add-Content", "Remove-Item",
        "Get-ItemProperty", "Set-ItemProperty", "HKCU:", "HKLM:",
        
        # --- Network ---
        "System.Net.WebClient", "UploadData", "DownloadData", "Invoke-RestMethod",
        "TcpClient", "UdpClient", "Dns.GetHostAddresses",
        
        # --- Privilege Abuse ---
        "Add-MpPreference", "Set-MpPreference", "Bypass", "ExecutionPolicy",
        "RunAs", "schtasks", "Start-Service", "Stop-Service"
    ],
    
    "bat": [
        # --- File / Execution ---
        "echo off", "start ", "call ", "goto ", "if exist", "for /f", "set ",
        "del /f /q", "copy ", "move ", "ren ", "attrib +h",
        
        # --- Registry / Persistence ---
        "reg add", "reg delete", "reg query", "schtasks /create",
        "schtasks /run", "sc start", "sc stop",
        
        # --- Dangerous Commands ---
        "format ", "bootcfg ", "bcdedit ", "net user", "net localgroup",
        "shutdown /s", "shutdown /r", "taskkill /f", "ping -n",
        
        # --- Network ---
        "ftp -s", "tftp ", "wget ", "curl ", "powershell -enc",
        
        # --- Obfuscation ---
        "^", "%%", "!!", "%random%", "%temp%", "%appdata%"
    ],
    
    "sh": [
        # --- Execution / File ---
        "chmod +x", "chown ", "cp ", "mv ", "rm -rf /", "dd if=", "mkfs ",
        "mount ", "umount ", "ln -s", "nohup ", "eval ",
        
        # --- Network ---
        "curl ", "wget ", "ftp ", "scp ", "sftp ", "nc -e", "telnet ",
        "exec 5<>/dev/tcp/", "bash -i >& /dev/tcp/", "python -c 'import socket'",
        
        # --- Persistence ---
        "crontab -e", "systemctl enable", "update-rc.d", "init.d", "rc.local",
        
        # --- Obfuscation ---
        "base64 ", "xxd ", "od ", "rev ", "tr -d", "eval $(echo",
        
        # --- Privilege Abuse ---
        "sudo ", "su root", "passwd ", "adduser ", "usermod ", "visudo",
        "setuid(", "setgid(", "ptrace", "LD_PRELOAD"
    ]
    },

    "exe": [
        # 🔹 Keyboard Hooking & Logging
        "SetWindowsHookEx", "WH_KEYBOARD_LL", "LowLevelKeyboardProc",
        "GetAsyncKeyState", "keybd_event", "GetForegroundWindow",
        "GetWindowTextA", "GetWindowTextW",

        # 🔹 Persistence (Registry / Startup)
        "RegOpenKey", "RegSetValue", "RegCreateKey", "RunServices",
        "RunOnce", "Winlogon", "Userinit",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "schtasks.exe",

        # 🔹 File/Data Logging
        "log.txt", "keys.txt", "keystrokes.txt", "data.db", "CreateFileA", "WriteFile",

        # 🔹 Exfiltration / Networking (Keylogger-specific)
        "HttpSendRequest", "InternetOpen", "InternetConnect",
        "InternetReadFile", "URLDownloadToFile", "sendmail", "exfil", "upload",

        # 🔹 Audio / Screen Capture
        "WaveInOpen", "WaveInStart", "RecordAudio", "camcapture", "screenshot", "logonui.exe"
    ],

    "dll": [
    # --- DLL Injection / API Hooking ---
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "FreeLibrary",
    "SetWindowsHookEx", "UnhookWindowsHookEx", "CallNextHookEx",
    "GetModuleHandle", "GetModuleHandleA", "GetModuleHandleW",
    "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory",
    
    # --- Process Injection ---
    "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC",
    "RtlCreateUserThread", "ZwMapViewOfSection",
    
    # --- Persistence (DLL Hijacking) ---
    "AppInit_DLLs", "KnownDLLs", "LoadAppInit_DLLs", "IFEO",
    "Image File Execution Options", "dllhost.exe", "rundll32.exe",
    
    # --- Keylogger-related Hooks ---
    "WH_KEYBOARD", "WH_KEYBOARD_LL", "WH_MOUSE_LL",
    "GetAsyncKeyState", "GetForegroundWindow",
    "MapVirtualKey", "ToUnicodeEx",
    
    # --- Networking inside DLLs ---
    "WSAStartup", "WSASocket", "send", "recv", "socket", "connect",
    "InternetOpen", "InternetOpenUrl", "InternetReadFile",
    "WinHttpOpen", "WinHttpConnect", "HttpSendRequest",
    
    # --- Suspicious Strings / Obfuscation ---
    "Base64Decode", "xor", "AES", "RC4", "DES", "keylogger",
    "C2", "exfil", "payload", "shellcode", "ReflectiveLoader",
    "DllMain", "ProxyDll"
    ],

    "src": [
    # --- Process & Execution ---
    "CreateProcess", "WinExec", "ShellExecute", "rundll32.exe",
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "system(", "exec(", "popen(", "ShellExecuteEx",
    
    # --- Memory Injection ---
    "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "QueueUserAPC", "ReflectiveLoader",
    
    # --- Keylogger Hooks ---
    "SetWindowsHookEx", "UnhookWindowsHookEx", "CallNextHookEx",
    "WH_KEYBOARD", "WH_KEYBOARD_LL", "WH_MOUSE_LL",
    "GetAsyncKeyState", "GetForegroundWindow",
    "MapVirtualKey", "ToUnicodeEx",
    
    # --- Persistence ---
    "AppInit_DLLs", "RunOnce", "Startup", "IFEO",
    "Image File Execution Options", "ScheduledTask",
    "Registry\\Run", "Registry\\RunOnce",
    
    # --- Networking ---
    "WSAStartup", "WSASocket", "socket", "send", "recv", "connect",
    "HttpSendRequest", "InternetOpenUrl", "WinHttpOpen",
    "WinHttpConnect", "InternetReadFile",
    
    # --- Suspicious Strings / Obfuscation ---
    "Base64Decode", "xor", "AES", "RC4", "DES", "keylogger",
    "C2", "payload", "exfil", "reverse shell", "persistence",
    "InstallHook", "Logger", "Backdoor"
    ],
    "cmd": [
    # --- Basic Batch Commands ---
    "echo off", "start ", "call ", "exit /b", "goto ", "pause", "title ",
    "color ", "set ", "for /f", "if exist", "if not exist",
    
    # --- File / Folder Operations ---
    "del /f /q", "erase ", "copy ", "xcopy ", "robocopy ",
    "move ", "ren ", "attrib +h", "attrib -h",
    
    # --- Registry / Persistence ---
    "reg add", "reg delete", "reg query", "reg import", "reg export",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "schtasks /create", "schtasks /run", "sc config", "sc create",
    
    # --- Dangerous Commands ---
    "format ", "bootcfg ", "bcdedit ", "net user", "net localgroup",
    "shutdown /s", "shutdown /r", "taskkill /f /im",
    "wmic process call create", "wmic os get", "whoami",
    
    # --- Network / Downloaders ---
    "ftp -s", "tftp -i", "powershell -enc", "bitsadmin /transfer",
    "certutil -urlcache", "certutil -decode", "curl ", "wget ",
    "nc -e", "telnet ",
    
    # --- Obfuscation ---
    "^", "%%", "!!", "%random%", "%temp%", "%appdata%", "%systemroot%",
    "hidden.vbs", ">>nul", "1>nul 2>nul",
    
    # --- Suspicious Behavior ---
    "rundll32.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "keylogger", "payload", "reverse shell", "logger",
    "copy *.exe", "echo [autorun] > autorun.inf"
    ],

    "pyw": [
    # --- Keylogger & Input Hooks ---
    "pynput", "keyboard", "mouse", "pyxhook", "pyHook", "pywin32",
    "win32api", "win32con", "win32gui", "win32clipboard",
    "GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx",
    "UnhookWindowsHookEx", "CallNextHookEx", "keybd_event",
    "SendInput", "MapVirtualKey", "GetForegroundWindow",
    "GetWindowText", "GetCursorPos",
    
    # --- File Logging ---
    "open(", "write(", "logging.basicConfig", "log.txt",
    "keystroke", "append(", "writelines", "rotatingfilehandler",
    "with open", "flush", "logfile", "hidden_log",
    
    # --- Silent Execution (unique to pyw) ---
    "pythonw.exe", "subprocess.Popen", "DETACHED_PROCESS",
    "CREATE_NO_WINDOW", "startupinfo", "si.dwFlags",
    "win32com.shell", "SW_HIDE",
    
    # --- Persistence ---
    "winreg", "Registry", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Startup", "os.startfile", "shutil.copy", "atexit",
    "sys.argv", "PyInstaller", "sched", "multiprocessing",
    
    # --- Network Exfiltration ---
    "requests", "socket", "smtplib", "urllib", "ftplib",
    "telnetlib", "paramiko", "websocket", "asyncio.open_connection",
    "aiohttp", "httpx", "Telegram", "Discord webhook",
    
    # --- Crypto & Obfuscation ---
    "base64", "fernet", "cryptography", "AES", "RSA",
    "xor", "md5", "sha256", "binascii", "marshal",
    "zlib", "exec(", "eval(", "compile(",
    
    # --- Clipboard & Screen Capture ---
    "pyperclip", "clipboard", "GetClipboardData", "EmptyClipboard",
    "OpenClipboard", "ImageGrab", "pyscreenshot", "mss",
    
    # --- Suspicious Indicators ---
    "stealth", "spy", "logger", "exfil", "C2",
    "reverse shell", "rat", "key capture", "background thread",
    "daemon=True", "service", "payload"
    ],

    "rb": [
    # --- Keylogger / Input Capture ---
    "io/console", "STDIN.getch", "STDIN.raw", "Curses", "ffi",
    "dl/import", "Win32API", "Xlib", "io/wait", "keylogger",
    "read_nonblock", "select { |input| input == STDIN }",
    
    # --- File Logging ---
    "File.open", "File.write", "IO.sysopen", "IO.binwrite",
    "log.txt", "keystroke", "append", "flush", "hidden.log",
    
    # --- Network Exfiltration ---
    "Net::HTTP", "Net::FTP", "Net::Telnet", "Net::SMTP",
    "TCPSocket", "UDPSocket", "Socket.new", "Open3.popen3",
    "RestClient", "curb", "httparty", "Excon", "em-http-request",
    "reverse_shell", "bind_shell", "C2", "payload",
    
    # --- Persistence ---
    "cron", "crontab", "systemd", "launchd", "atd", "rc.local",
    "Win32::Registry", "ENV['APPDATA']", "ENV['TEMP']",
    "autorun", "Startup", "schtasks",
    
    # --- Process / Execution ---
    "system(", "exec(", "spawn(", "Open3.capture3",
    "Kernel.fork", "Thread.new", "Process.kill", "Process.daemon",
    "require 'open3'", "eval(", "instance_eval", "class_eval",
    
    # --- Crypto & Obfuscation ---
    "Base64.decode64", "OpenSSL::Cipher", "AES.new", "RSA.new",
    "Digest::MD5", "Digest::SHA256", "xor", "pack('m')",
    "unpack('m')", "Zlib::Inflate", "Marshal.load",
    "eval(Base64.decode64", "obfuscate",
    
    # --- Clipboard / Screen Capture ---
    "clipboard", "xclip", "xsel", "pbpaste", "pbcopy",
    "screencap", "screenshot", "imagemagick", "rmagick",
    "chunky_png", "gtk2", "Qt::Clipboard",
    
    # --- Suspicious Indicators ---
    "logger", "stealth", "spy", "daemonize", "background",
    "exfiltrate", "keystrokes", "C2 server", "inject",
    "payload", "rootkit", "trojan"
    ],

    "office" : [
    # --- Macro Abuse ---
    "AutoOpen", "Document_Open", "Workbook_Open", "PresentationOpen",
    "AutoClose", "Document_Close", "Workbook_BeforeClose",
    "Sub ", "End Sub", "Function ", "End Function",
    "ActiveDocument", "ActiveWorkbook", "ActivePresentation",
    "Selection", "Range(", "Cells(", "Slides(",

    # --- Scripting / Execution ---
    "Shell(", "WScript.Shell", "CreateObject", "GetObject",
    "ShellExecute", "Environ(", "MsgBox", "Execute(", "Run(",
    "cmd.exe", "powershell", "mshta", "wscript", "cscript",

    # --- External Connections ---
    "http://", "https://", "ftp://", "smb://", "\\\\",
    "DownloadFile", "ADODB.Stream", "XMLHTTP", "WinHttp.WinHttpRequest",
    "URLDownloadToFile", "Msxml2.XMLHTTP",

    # --- Encoding / Obfuscation ---
    "Base64Decode", "Base64String", "HexDecode", "Chr(", "Asc(",
    "StrReverse", "Xor", "Rot13", "eval(", "ExecuteGlobal",

    # --- Embedded Payloads ---
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    "MZ", "This program cannot be run", "PK", "OLEObject",
    "ActiveXObject", "UserForm", "OLE2Link", "ObjectPool",

    # --- Persistence Attempts ---
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "StartupFolder", "AutoExec",

    # --- Indicators of Attack ---
    "MalDoc", "Dropper", "Exploit", "Macro Virus",
    "Payload", "Keylogger", "Trojan", "RAT"
],

    "img": [
    # general spyware / keylogger libs & terms
    "pynput", "keyboard", "keylogger", "keystroke", "keylog", "key_logs", "record_keys",
    "getasynckeystate", "setwindowshookex", "unhookwindowshookex", "callnexthookex",
    "wh_keyboard_ll", "lowlevelkeyboardproc", "sendinput",

    # common script/language markers (possible embedded code)
    "import ", "from ", "exec(", "eval(", "compile(", "execfile", "system(", "subprocess",
    "python", "pythonw", "powershell", "pwsh", "cmd.exe", "bash -c", "sh -c",

    # exfil / network / C2 markers
    "socket", "connect(", "send(", "recv(", "http://", "https://", "ftp://", "telnet",
    "webhook", "telegram", "discord", "api.telegram", "POST /", "GET /", "upload", "exfil",

    # archive / container / embedded file signatures
    "PK\x03\x04", "PK03", "PK", "MZ", "This program cannot be run", "%PDF-", "Rar!", "7z",
    "ustar", "gzip", "BZh", "tar", "xz", "7-Zip",

    # base64 / encoding / obfuscation indicators
    "base64", "b64_decode", "b64encode", "FromBase64String", "base64decode",
    "strrev", "str_reverse", "rot13", "xor", "hex(", "unpack('m')", "pack('m')",
    "zzencode", "eval(base64", "atob(", "btoa(",

    # common file extensions attackers append/encode
    ".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".py", ".pyw",
    ".sh", ".pl", ".rb", ".jar", ".jar!", ".so", ".dylib",

    # common filenames & log names
    "log.txt", "keys.txt", "keylog.txt", "keystrokes.txt", "capture.log", "data.bin",
    "payload.bin", "dropper", "loader", "stager", "agent", "agent.exe",

    # steganography tool strings / heuristics
    "steg", "steganography", "lsb", "least significant bit", "stegano", "openstego",
    "stegdetect", "stegsolve", "steganogan", "hidden data", "embedded data",

    # metadata / EXIF / tEXt indicators
    "exif", "exif:Software", "exif:UserComment", "exif:ImageDescription",
    "tEXt", "iTXt", "Comment", "Description", "UserComment", "XPComment",

    # scripting / powershell obfuscation tokens
    "-EncodedCommand", "-enc", "IEX", "Invoke-Expression", "DownloadString", "New-Object Net.WebClient",
    "Invoke-WebRequest", "-NoProfile", "-WindowStyle Hidden", "-ExecutionPolicy Bypass",

    # binary / PE / ELF markers in raw bytes
    "PE\\x00\\x00", "ELF", "shc", "MZ!", "MZ\\x90", "DOS", "IMAGE_NT_HEADERS",

    # keywords referencing tools / packers / crypters
    "UPX", "Themida", "VMProtect", "Enigma Protector", "ASPack", "NSIS", "PyInstaller",

    # suspicious command strings
    "cmd /c", "cmd /k", "powershell -nop", "powershell -w hidden", "curl ", "wget ", "certutil -decode",
    "certutil -urlcache", "bitsadmin /transfer", "rundll32.exe", "reg add", "reg import",

    # long-blob & entropy hints
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "////", "++++", "====", "verylongbase64", "randomdata",
    "-----BEGIN", "-----END", "BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY", "-----BEGIN PGP",

    # strings indicating embedded scripts or macros
    "vbaProject.bin", "AutoOpen", "Macro", "MacroButton", "Application.OnTime", "Application.OnKey",
    "CreateObject", "WScript.Shell", "ActiveXObject", "ADODB.Stream", "MSXML2.XMLHTTP",

    # contact / exfil endpoints and credentials patterns
    "username=", "password=", "passwd=", "token=", "api_key", "auth=", "Authorization:", "Bearer ",

    # clipboard / screenshot / audio capture libs
    "pyperclip", "clipboard", "ImageGrab", "pyscreenshot", "mss", "pyaudio", "sounddevice", "wave.open",

    # indicators of appended plaintext/code
    "import socket", "import requests", "import pynput", "from pynput", "def on_press", "def main(", "if __name__",

    # suspicious English words often used in malicious drops
    "dropper", "installer", "updater", "unpack", "decrypt", "decryptor", "obfuscate", "packer", "loader",

    # Windows-specific persistence & autorun markers
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "StartupFolder", "RunOnce", "IFEO",

    # networking protocols / ports / C2 phrases
    "C2", "command and control", "callback", "reverse shell", "bind shell", "connectback", "beacon",

    # common short-coded obfuscation fragments
    "\\x00\\x01\\x02", "\\x90\\x90\\x90", "\\xDE\\xAD\\xBE\\xEF", "\\xCC\\xCC", "\\xff\\xd9",  # ff d9 = JPEG EOF
    "\\x89PNG", "\\x50\\x4B\\x03\\x04",  # PNG, ZIP

    # archive-in-image markers / nested archive names
    "embedded.zip", "embedded.rar", "inner.zip", "payload.zip", "archive.zip", "vbaProject", "word/vbaProject.bin",

    # common remote control / RAT names & terms (generic)
    "rat", "reverse_tcp", "meterpreter", "shellcode", "bind_tcp", "nc -e", "netcat", "socat",

    # suspicious MIME / content-range clues
    "application/octet-stream", "application/x-msdownload", "application/zip",
    "Content-Disposition:", "filename=", "Content-Transfer-Encoding:", "base64",

    # HTTP markers used by exfil / C2
    "/api/", "/upload", "/submit", "/data", "/report", "/beacon", "User-Agent:", "Referer:", "Authorization:",

    # more generic obfuscation / unusual patterns
    "String.fromCharCode", "String.fromCharCodes", "unescape(", "escape(", "atob(", "btoa(",

    # signs of multi-part or concatenated payloads
    "--boundary", "Content-Type: multipart", "Content-Encoding: gzip", "PKZIP", "ZIP64",

    # hints of stego tools and forensic artifacts
    "steghide", "steghide extract", "outguess", "openstego", "steghide", "silentink", "stegextract",

    # common C/C++ style indicators embedded as text
    "printf(", "fwrite(", "fopen(", "CreateFileA", "WriteFile", "ReadFile", "LoadLibraryA"
],

"png": [
    # general spyware / keylogger libs & terms
    "pynput", "keyboard", "keylogger", "keystroke", "keylog", "key_logs", "record_keys",
    "getasynckeystate", "setwindowshookex", "unhookwindowshookex", "callnexthookex",
    "wh_keyboard_ll", "lowlevelkeyboardproc", "sendinput",

    # common script/language markers (possible embedded code)
    "import ", "from ", "exec(", "eval(", "compile(", "execfile", "system(", "subprocess",
    "python", "pythonw", "powershell", "pwsh", "cmd.exe", "bash -c", "sh -c",

    # exfil / network / C2 markers
    "socket", "connect(", "send(", "recv(", "http://", "https://", "ftp://", "telnet",
    "webhook", "telegram", "discord", "api.telegram", "POST /", "GET /", "upload", "exfil",

    # archive / container / embedded file signatures
    "PK\x03\x04", "PK03", "PK", "MZ", "This program cannot be run", "%PDF-", "Rar!", "7z",
    "ustar", "gzip", "BZh", "tar", "xz", "7-Zip",

    # base64 / encoding / obfuscation indicators
    "base64", "b64_decode", "b64encode", "FromBase64String", "base64decode",
    "strrev", "str_reverse", "rot13", "xor", "hex(", "unpack('m')", "pack('m')",
    "zzencode", "eval(base64", "atob(", "btoa(",

    # common file extensions attackers append/encode
    ".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".py", ".pyw",
    ".sh", ".pl", ".rb", ".jar", ".jar!", ".so", ".dylib",

    # common filenames & log names
    "log.txt", "keys.txt", "keylog.txt", "keystrokes.txt", "capture.log", "data.bin",
    "payload.bin", "dropper", "loader", "stager", "agent", "agent.exe",

    # steganography tool strings / heuristics
    "steg", "steganography", "lsb", "least significant bit", "stegano", "openstego",
    "stegdetect", "stegsolve", "steganogan", "hidden data", "embedded data",

    # metadata / EXIF / tEXt indicators
    "exif", "exif:Software", "exif:UserComment", "exif:ImageDescription",
    "tEXt", "iTXt", "Comment", "Description", "UserComment", "XPComment",

    # scripting / powershell obfuscation tokens
    "-EncodedCommand", "-enc", "IEX", "Invoke-Expression", "DownloadString", "New-Object Net.WebClient",
    "Invoke-WebRequest", "-NoProfile", "-WindowStyle Hidden", "-ExecutionPolicy Bypass",

    # binary / PE / ELF markers in raw bytes
    "PE\\x00\\x00", "ELF", "shc", "MZ!", "MZ\\x90", "DOS", "IMAGE_NT_HEADERS",

    # keywords referencing tools / packers / crypters
    "UPX", "Themida", "VMProtect", "Enigma Protector", "ASPack", "NSIS", "PyInstaller",

    # suspicious command strings
    "cmd /c", "cmd /k", "powershell -nop", "powershell -w hidden", "curl ", "wget ", "certutil -decode",
    "certutil -urlcache", "bitsadmin /transfer", "rundll32.exe", "reg add", "reg import",

    # long-blob & entropy hints
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "////", "++++", "====", "verylongbase64", "randomdata",
    "-----BEGIN", "-----END", "BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY", "-----BEGIN PGP",

    # strings indicating embedded scripts or macros
    "vbaProject.bin", "AutoOpen", "Macro", "MacroButton", "Application.OnTime", "Application.OnKey",
    "CreateObject", "WScript.Shell", "ActiveXObject", "ADODB.Stream", "MSXML2.XMLHTTP",

    # contact / exfil endpoints and credentials patterns
    "username=", "password=", "passwd=", "token=", "api_key", "auth=", "Authorization:", "Bearer ",

    # clipboard / screenshot / audio capture libs
    "pyperclip", "clipboard", "ImageGrab", "pyscreenshot", "mss", "pyaudio", "sounddevice", "wave.open",

    # indicators of appended plaintext/code
    "import socket", "import requests", "import pynput", "from pynput", "def on_press", "def main(", "if __name__",

    # suspicious English words often used in malicious drops
    "dropper", "installer", "updater", "unpack", "decrypt", "decryptor", "obfuscate", "packer", "loader",

    # Windows-specific persistence & autorun markers
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "StartupFolder", "RunOnce", "IFEO",

    # networking protocols / ports / C2 phrases
    "C2", "command and control", "callback", "reverse shell", "bind shell", "connectback", "beacon",

    # common short-coded obfuscation fragments
    "\\x00\\x01\\x02", "\\x90\\x90\\x90", "\\xDE\\xAD\\xBE\\xEF", "\\xCC\\xCC", "\\xff\\xd9",  # ff d9 = JPEG EOF
    "\\x89PNG", "\\x50\\x4B\\x03\\x04",  # PNG, ZIP

    # archive-in-image markers / nested archive names
    "embedded.zip", "embedded.rar", "inner.zip", "payload.zip", "archive.zip", "vbaProject", "word/vbaProject.bin",

    # common remote control / RAT names & terms (generic)
    "rat", "reverse_tcp", "meterpreter", "shellcode", "bind_tcp", "nc -e", "netcat", "socat",

    # suspicious MIME / content-range clues
    "application/octet-stream", "application/x-msdownload", "application/zip",
    "Content-Disposition:", "filename=", "Content-Transfer-Encoding:", "base64",

    # HTTP markers used by exfil / C2
    "/api/", "/upload", "/submit", "/data", "/report", "/beacon", "User-Agent:", "Referer:", "Authorization:",

    # more generic obfuscation / unusual patterns
    "String.fromCharCode", "String.fromCharCodes", "unescape(", "escape(", "atob(", "btoa(",

    # signs of multi-part or concatenated payloads
    "--boundary", "Content-Type: multipart", "Content-Encoding: gzip", "PKZIP", "ZIP64",

    # hints of stego tools and forensic artifacts
    "steghide", "steghide extract", "outguess", "openstego", "steghide", "silentink", "stegextract",

    # common C/C++ style indicators embedded as text
    "printf(", "fwrite(", "fopen(", "CreateFileA", "WriteFile", "ReadFile", "LoadLibraryA"
],

    "jpg": [
    # general spyware / keylogger libs & terms
    "pynput", "keyboard", "keylogger", "keystroke", "keylog", "key_logs", "record_keys",
    "getasynckeystate", "setwindowshookex", "unhookwindowshookex", "callnexthookex",
    "wh_keyboard_ll", "lowlevelkeyboardproc", "sendinput",

    # common script/language markers (possible embedded code)
    "import ", "from ", "exec(", "eval(", "compile(", "execfile", "system(", "subprocess",
    "python", "pythonw", "powershell", "pwsh", "cmd.exe", "bash -c", "sh -c",

    # exfil / network / C2 markers
    "socket", "connect(", "send(", "recv(", "http://", "https://", "ftp://", "telnet",
    "webhook", "telegram", "discord", "api.telegram", "POST /", "GET /", "upload", "exfil",

    # archive / container / embedded file signatures
    "PK\x03\x04", "PK03", "PK", "MZ", "This program cannot be run", "%PDF-", "Rar!", "7z",
    "ustar", "gzip", "BZh", "tar", "xz", "7-Zip",

    # base64 / encoding / obfuscation indicators
    "base64", "b64_decode", "b64encode", "FromBase64String", "base64decode",
    "strrev", "str_reverse", "rot13", "xor", "hex(", "unpack('m')", "pack('m')",
    "zzencode", "eval(base64", "atob(", "btoa(",

    # common file extensions attackers append/encode
    ".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".py", ".pyw",
    ".sh", ".pl", ".rb", ".jar", ".jar!", ".so", ".dylib",

    # common filenames & log names
    "log.txt", "keys.txt", "keylog.txt", "keystrokes.txt", "capture.log", "data.bin",
    "payload.bin", "dropper", "loader", "stager", "agent", "agent.exe",

    # steganography tool strings / heuristics
    "steg", "steganography", "lsb", "least significant bit", "stegano", "openstego",
    "stegdetect", "stegsolve", "steganogan", "hidden data", "embedded data",

    # metadata / EXIF / tEXt indicators
    "exif", "exif:Software", "exif:UserComment", "exif:ImageDescription",
    "tEXt", "iTXt", "Comment", "Description", "UserComment", "XPComment",

    # scripting / powershell obfuscation tokens
    "-EncodedCommand", "-enc", "IEX", "Invoke-Expression", "DownloadString", "New-Object Net.WebClient",
    "Invoke-WebRequest", "-NoProfile", "-WindowStyle Hidden", "-ExecutionPolicy Bypass",

    # binary / PE / ELF markers in raw bytes
    "PE\\x00\\x00", "ELF", "shc", "MZ!", "MZ\\x90", "DOS", "IMAGE_NT_HEADERS",

    # keywords referencing tools / packers / crypters
    "UPX", "Themida", "VMProtect", "Enigma Protector", "ASPack", "NSIS", "PyInstaller",

    # suspicious command strings
    "cmd /c", "cmd /k", "powershell -nop", "powershell -w hidden", "curl ", "wget ", "certutil -decode",
    "certutil -urlcache", "bitsadmin /transfer", "rundll32.exe", "reg add", "reg import",

    # long-blob & entropy hints
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "////", "++++", "====", "verylongbase64", "randomdata",
    "-----BEGIN", "-----END", "BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY", "-----BEGIN PGP",

    # strings indicating embedded scripts or macros
    "vbaProject.bin", "AutoOpen", "Macro", "MacroButton", "Application.OnTime", "Application.OnKey",
    "CreateObject", "WScript.Shell", "ActiveXObject", "ADODB.Stream", "MSXML2.XMLHTTP",

    # contact / exfil endpoints and credentials patterns
    "username=", "password=", "passwd=", "token=", "api_key", "auth=", "Authorization:", "Bearer ",

    # clipboard / screenshot / audio capture libs
    "pyperclip", "clipboard", "ImageGrab", "pyscreenshot", "mss", "pyaudio", "sounddevice", "wave.open",

    # indicators of appended plaintext/code
    "import socket", "import requests", "import pynput", "from pynput", "def on_press", "def main(", "if __name__",

    # suspicious English words often used in malicious drops
    "dropper", "installer", "updater", "unpack", "decrypt", "decryptor", "obfuscate", "packer", "loader",

    # Windows-specific persistence & autorun markers
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "StartupFolder", "RunOnce", "IFEO",

    # networking protocols / ports / C2 phrases
    "C2", "command and control", "callback", "reverse shell", "bind shell", "connectback", "beacon",

    # common short-coded obfuscation fragments
    "\\x00\\x01\\x02", "\\x90\\x90\\x90", "\\xDE\\xAD\\xBE\\xEF", "\\xCC\\xCC", "\\xff\\xd9",  # ff d9 = JPEG EOF
    "\\x89PNG", "\\x50\\x4B\\x03\\x04",  # PNG, ZIP

    # archive-in-image markers / nested archive names
    "embedded.zip", "embedded.rar", "inner.zip", "payload.zip", "archive.zip", "vbaProject", "word/vbaProject.bin",

    # common remote control / RAT names & terms (generic)
    "rat", "reverse_tcp", "meterpreter", "shellcode", "bind_tcp", "nc -e", "netcat", "socat",

    # suspicious MIME / content-range clues
    "application/octet-stream", "application/x-msdownload", "application/zip",
    "Content-Disposition:", "filename=", "Content-Transfer-Encoding:", "base64",

    # HTTP markers used by exfil / C2
    "/api/", "/upload", "/submit", "/data", "/report", "/beacon", "User-Agent:", "Referer:", "Authorization:",

    # more generic obfuscation / unusual patterns
    "String.fromCharCode", "String.fromCharCodes", "unescape(", "escape(", "atob(", "btoa(",

    # signs of multi-part or concatenated payloads
    "--boundary", "Content-Type: multipart", "Content-Encoding: gzip", "PKZIP", "ZIP64",

    # hints of stego tools and forensic artifacts
    "steghide", "steghide extract", "outguess", "openstego", "steghide", "silentink", "stegextract",

    # common C/C++ style indicators embedded as text
    "printf(", "fwrite(", "fopen(", "CreateFileA", "WriteFile", "ReadFile", "LoadLibraryA"
],

    "jpeg": [
    # general spyware / keylogger libs & terms
    "pynput", "keyboard", "keylogger", "keystroke", "keylog", "key_logs", "record_keys",
    "getasynckeystate", "setwindowshookex", "unhookwindowshookex", "callnexthookex",
    "wh_keyboard_ll", "lowlevelkeyboardproc", "sendinput",

    # common script/language markers (possible embedded code)
    "import ", "from ", "exec(", "eval(", "compile(", "execfile", "system(", "subprocess",
    "python", "pythonw", "powershell", "pwsh", "cmd.exe", "bash -c", "sh -c",

    # exfil / network / C2 markers
    "socket", "connect(", "send(", "recv(", "http://", "https://", "ftp://", "telnet",
    "webhook", "telegram", "discord", "api.telegram", "POST /", "GET /", "upload", "exfil",

    # archive / container / embedded file signatures
    "PK\x03\x04", "PK03", "PK", "MZ", "This program cannot be run", "%PDF-", "Rar!", "7z",
    "ustar", "gzip", "BZh", "tar", "xz", "7-Zip",

    # base64 / encoding / obfuscation indicators
    "base64", "b64_decode", "b64encode", "FromBase64String", "base64decode",
    "strrev", "str_reverse", "rot13", "xor", "hex(", "unpack('m')", "pack('m')",
    "zzencode", "eval(base64", "atob(", "btoa(",

    # common file extensions attackers append/encode
    ".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".py", ".pyw",
    ".sh", ".pl", ".rb", ".jar", ".jar!", ".so", ".dylib",

    # common filenames & log names
    "log.txt", "keys.txt", "keylog.txt", "keystrokes.txt", "capture.log", "data.bin",
    "payload.bin", "dropper", "loader", "stager", "agent", "agent.exe",

    # steganography tool strings / heuristics
    "steg", "steganography", "lsb", "least significant bit", "stegano", "openstego",
    "stegdetect", "stegsolve", "steganogan", "hidden data", "embedded data",

    # metadata / EXIF / tEXt indicators
    "exif", "exif:Software", "exif:UserComment", "exif:ImageDescription",
    "tEXt", "iTXt", "Comment", "Description", "UserComment", "XPComment",

    # scripting / powershell obfuscation tokens
    "-EncodedCommand", "-enc", "IEX", "Invoke-Expression", "DownloadString", "New-Object Net.WebClient",
    "Invoke-WebRequest", "-NoProfile", "-WindowStyle Hidden", "-ExecutionPolicy Bypass",

    # binary / PE / ELF markers in raw bytes
    "PE\\x00\\x00", "ELF", "shc", "MZ!", "MZ\\x90", "DOS", "IMAGE_NT_HEADERS",

    # keywords referencing tools / packers / crypters
    "UPX", "Themida", "VMProtect", "Enigma Protector", "ASPack", "NSIS", "PyInstaller",

    # suspicious command strings
    "cmd /c", "cmd /k", "powershell -nop", "powershell -w hidden", "curl ", "wget ", "certutil -decode",
    "certutil -urlcache", "bitsadmin /transfer", "rundll32.exe", "reg add", "reg import",

    # long-blob & entropy hints
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "////", "++++", "====", "verylongbase64", "randomdata",
    "-----BEGIN", "-----END", "BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY", "-----BEGIN PGP",

    # strings indicating embedded scripts or macros
    "vbaProject.bin", "AutoOpen", "Macro", "MacroButton", "Application.OnTime", "Application.OnKey",
    "CreateObject", "WScript.Shell", "ActiveXObject", "ADODB.Stream", "MSXML2.XMLHTTP",

    # contact / exfil endpoints and credentials patterns
    "username=", "password=", "passwd=", "token=", "api_key", "auth=", "Authorization:", "Bearer ",

    # clipboard / screenshot / audio capture libs
    "pyperclip", "clipboard", "ImageGrab", "pyscreenshot", "mss", "pyaudio", "sounddevice", "wave.open",

    # indicators of appended plaintext/code
    "import socket", "import requests", "import pynput", "from pynput", "def on_press", "def main(", "if __name__",

    # suspicious English words often used in malicious drops
    "dropper", "installer", "updater", "unpack", "decrypt", "decryptor", "obfuscate", "packer", "loader",

    # Windows-specific persistence & autorun markers
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "StartupFolder", "RunOnce", "IFEO",

    # networking protocols / ports / C2 phrases
    "C2", "command and control", "callback", "reverse shell", "bind shell", "connectback", "beacon",

    # common short-coded obfuscation fragments
    "\\x00\\x01\\x02", "\\x90\\x90\\x90", "\\xDE\\xAD\\xBE\\xEF", "\\xCC\\xCC", "\\xff\\xd9",  # ff d9 = JPEG EOF
    "\\x89PNG", "\\x50\\x4B\\x03\\x04",  # PNG, ZIP

    # archive-in-image markers / nested archive names
    "embedded.zip", "embedded.rar", "inner.zip", "payload.zip", "archive.zip", "vbaProject", "word/vbaProject.bin",

    # common remote control / RAT names & terms (generic)
    "rat", "reverse_tcp", "meterpreter", "shellcode", "bind_tcp", "nc -e", "netcat", "socat",

    # suspicious MIME / content-range clues
    "application/octet-stream", "application/x-msdownload", "application/zip",
    "Content-Disposition:", "filename=", "Content-Transfer-Encoding:", "base64",

    # HTTP markers used by exfil / C2
    "/api/", "/upload", "/submit", "/data", "/report", "/beacon", "User-Agent:", "Referer:", "Authorization:",

    # more generic obfuscation / unusual patterns
    "String.fromCharCode", "String.fromCharCodes", "unescape(", "escape(", "atob(", "btoa(",

    # signs of multi-part or concatenated payloads
    "--boundary", "Content-Type: multipart", "Content-Encoding: gzip", "PKZIP", "ZIP64",

    # hints of stego tools and forensic artifacts
    "steghide", "steghide extract", "outguess", "openstego", "steghide", "silentink", "stegextract",

    # common C/C++ style indicators embedded as text
    "printf(", "fwrite(", "fopen(", "CreateFileA", "WriteFile", "ReadFile", "LoadLibraryA"
],

    "bmp": [
    # general spyware / keylogger libs & terms
    "pynput", "keyboard", "keylogger", "keystroke", "keylog", "key_logs", "record_keys",
    "getasynckeystate", "setwindowshookex", "unhookwindowshookex", "callnexthookex",
    "wh_keyboard_ll", "lowlevelkeyboardproc", "sendinput",

    # common script/language markers (possible embedded code)
    "import ", "from ", "exec(", "eval(", "compile(", "execfile", "system(", "subprocess",
    "python", "pythonw", "powershell", "pwsh", "cmd.exe", "bash -c", "sh -c",

    # exfil / network / C2 markers
    "socket", "connect(", "send(", "recv(", "http://", "https://", "ftp://", "telnet",
    "webhook", "telegram", "discord", "api.telegram", "POST /", "GET /", "upload", "exfil",

    # archive / container / embedded file signatures
    "PK\x03\x04", "PK03", "PK", "MZ", "This program cannot be run", "%PDF-", "Rar!", "7z",
    "ustar", "gzip", "BZh", "tar", "xz", "7-Zip",

    # base64 / encoding / obfuscation indicators
    "base64", "b64_decode", "b64encode", "FromBase64String", "base64decode",
    "strrev", "str_reverse", "rot13", "xor", "hex(", "unpack('m')", "pack('m')",
    "zzencode", "eval(base64", "atob(", "btoa(",

    # common file extensions attackers append/encode
    ".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".py", ".pyw",
    ".sh", ".pl", ".rb", ".jar", ".jar!", ".so", ".dylib",

    # common filenames & log names
    "log.txt", "keys.txt", "keylog.txt", "keystrokes.txt", "capture.log", "data.bin",
    "payload.bin", "dropper", "loader", "stager", "agent", "agent.exe",

    # steganography tool strings / heuristics
    "steg", "steganography", "lsb", "least significant bit", "stegano", "openstego",
    "stegdetect", "stegsolve", "steganogan", "hidden data", "embedded data",

    # metadata / EXIF / tEXt indicators
    "exif", "exif:Software", "exif:UserComment", "exif:ImageDescription",
    "tEXt", "iTXt", "Comment", "Description", "UserComment", "XPComment",

    # scripting / powershell obfuscation tokens
    "-EncodedCommand", "-enc", "IEX", "Invoke-Expression", "DownloadString", "New-Object Net.WebClient",
    "Invoke-WebRequest", "-NoProfile", "-WindowStyle Hidden", "-ExecutionPolicy Bypass",

    # binary / PE / ELF markers in raw bytes
    "PE\\x00\\x00", "ELF", "shc", "MZ!", "MZ\\x90", "DOS", "IMAGE_NT_HEADERS",

    # keywords referencing tools / packers / crypters
    "UPX", "Themida", "VMProtect", "Enigma Protector", "ASPack", "NSIS", "PyInstaller",

    # suspicious command strings
    "cmd /c", "cmd /k", "powershell -nop", "powershell -w hidden", "curl ", "wget ", "certutil -decode",
    "certutil -urlcache", "bitsadmin /transfer", "rundll32.exe", "reg add", "reg import",

    # long-blob & entropy hints
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "////", "++++", "====", "verylongbase64", "randomdata",
    "-----BEGIN", "-----END", "BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY", "-----BEGIN PGP",

    # strings indicating embedded scripts or macros
    "vbaProject.bin", "AutoOpen", "Macro", "MacroButton", "Application.OnTime", "Application.OnKey",
    "CreateObject", "WScript.Shell", "ActiveXObject", "ADODB.Stream", "MSXML2.XMLHTTP",

    # contact / exfil endpoints and credentials patterns
    "username=", "password=", "passwd=", "token=", "api_key", "auth=", "Authorization:", "Bearer ",

    # clipboard / screenshot / audio capture libs
    "pyperclip", "clipboard", "ImageGrab", "pyscreenshot", "mss", "pyaudio", "sounddevice", "wave.open",

    # indicators of appended plaintext/code
    "import socket", "import requests", "import pynput", "from pynput", "def on_press", "def main(", "if __name__",

    # suspicious English words often used in malicious drops
    "dropper", "installer", "updater", "unpack", "decrypt", "decryptor", "obfuscate", "packer", "loader",

    # Windows-specific persistence & autorun markers
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "StartupFolder", "RunOnce", "IFEO",

    # networking protocols / ports / C2 phrases
    "C2", "command and control", "callback", "reverse shell", "bind shell", "connectback", "beacon",

    # common short-coded obfuscation fragments
    "\\x00\\x01\\x02", "\\x90\\x90\\x90", "\\xDE\\xAD\\xBE\\xEF", "\\xCC\\xCC", "\\xff\\xd9",  # ff d9 = JPEG EOF
    "\\x89PNG", "\\x50\\x4B\\x03\\x04",  # PNG, ZIP

    # archive-in-image markers / nested archive names
    "embedded.zip", "embedded.rar", "inner.zip", "payload.zip", "archive.zip", "vbaProject", "word/vbaProject.bin",

    # common remote control / RAT names & terms (generic)
    "rat", "reverse_tcp", "meterpreter", "shellcode", "bind_tcp", "nc -e", "netcat", "socat",

    # suspicious MIME / content-range clues
    "application/octet-stream", "application/x-msdownload", "application/zip",
    "Content-Disposition:", "filename=", "Content-Transfer-Encoding:", "base64",

    # HTTP markers used by exfil / C2
    "/api/", "/upload", "/submit", "/data", "/report", "/beacon", "User-Agent:", "Referer:", "Authorization:",

    # more generic obfuscation / unusual patterns
    "String.fromCharCode", "String.fromCharCodes", "unescape(", "escape(", "atob(", "btoa(",

    # signs of multi-part or concatenated payloads
    "--boundary", "Content-Type: multipart", "Content-Encoding: gzip", "PKZIP", "ZIP64",

    # hints of stego tools and forensic artifacts
    "steghide", "steghide extract", "outguess", "openstego", "steghide", "silentink", "stegextract",

    # common C/C++ style indicators embedded as text
    "printf(", "fwrite(", "fopen(", "CreateFileA", "WriteFile", "ReadFile", "LoadLibraryA"
], 
    
    "gif": [
    # general spyware / keylogger libs & terms
    "pynput", "keyboard", "keylogger", "keystroke", "keylog", "key_logs", "record_keys",
    "getasynckeystate", "setwindowshookex", "unhookwindowshookex", "callnexthookex",
    "wh_keyboard_ll", "lowlevelkeyboardproc", "sendinput",

    # common script/language markers (possible embedded code)
    "import ", "from ", "exec(", "eval(", "compile(", "execfile", "system(", "subprocess",
    "python", "pythonw", "powershell", "pwsh", "cmd.exe", "bash -c", "sh -c",

    # exfil / network / C2 markers
    "socket", "connect(", "send(", "recv(", "http://", "https://", "ftp://", "telnet",
    "webhook", "telegram", "discord", "api.telegram", "POST /", "GET /", "upload", "exfil",

    # archive / container / embedded file signatures
    "PK\x03\x04", "PK03", "PK", "MZ", "This program cannot be run", "%PDF-", "Rar!", "7z",
    "ustar", "gzip", "BZh", "tar", "xz", "7-Zip",

    # base64 / encoding / obfuscation indicators
    "base64", "b64_decode", "b64encode", "FromBase64String", "base64decode",
    "strrev", "str_reverse", "rot13", "xor", "hex(", "unpack('m')", "pack('m')",
    "zzencode", "eval(base64", "atob(", "btoa(",

    # common file extensions attackers append/encode
    ".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".py", ".pyw",
    ".sh", ".pl", ".rb", ".jar", ".jar!", ".so", ".dylib",

    # common filenames & log names
    "log.txt", "keys.txt", "keylog.txt", "keystrokes.txt", "capture.log", "data.bin",
    "payload.bin", "dropper", "loader", "stager", "agent", "agent.exe",

    # steganography tool strings / heuristics
    "steg", "steganography", "lsb", "least significant bit", "stegano", "openstego",
    "stegdetect", "stegsolve", "steganogan", "hidden data", "embedded data",

    # metadata / EXIF / tEXt indicators
    "exif", "exif:Software", "exif:UserComment", "exif:ImageDescription",
    "tEXt", "iTXt", "Comment", "Description", "UserComment", "XPComment",

    # scripting / powershell obfuscation tokens
    "-EncodedCommand", "-enc", "IEX", "Invoke-Expression", "DownloadString", "New-Object Net.WebClient",
    "Invoke-WebRequest", "-NoProfile", "-WindowStyle Hidden", "-ExecutionPolicy Bypass",

    # binary / PE / ELF markers in raw bytes
    "PE\\x00\\x00", "ELF", "shc", "MZ!", "MZ\\x90", "DOS", "IMAGE_NT_HEADERS",

    # keywords referencing tools / packers / crypters
    "UPX", "Themida", "VMProtect", "Enigma Protector", "ASPack", "NSIS", "PyInstaller",

    # suspicious command strings
    "cmd /c", "cmd /k", "powershell -nop", "powershell -w hidden", "curl ", "wget ", "certutil -decode",
    "certutil -urlcache", "bitsadmin /transfer", "rundll32.exe", "reg add", "reg import",

    # long-blob & entropy hints
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "////", "++++", "====", "verylongbase64", "randomdata",
    "-----BEGIN", "-----END", "BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY", "-----BEGIN PGP",

    # strings indicating embedded scripts or macros
    "vbaProject.bin", "AutoOpen", "Macro", "MacroButton", "Application.OnTime", "Application.OnKey",
    "CreateObject", "WScript.Shell", "ActiveXObject", "ADODB.Stream", "MSXML2.XMLHTTP",

    # contact / exfil endpoints and credentials patterns
    "username=", "password=", "passwd=", "token=", "api_key", "auth=", "Authorization:", "Bearer ",

    # clipboard / screenshot / audio capture libs
    "pyperclip", "clipboard", "ImageGrab", "pyscreenshot", "mss", "pyaudio", "sounddevice", "wave.open",

    # indicators of appended plaintext/code
    "import socket", "import requests", "import pynput", "from pynput", "def on_press", "def main(", "if __name__",

    # suspicious English words often used in malicious drops
    "dropper", "installer", "updater", "unpack", "decrypt", "decryptor", "obfuscate", "packer", "loader",

    # Windows-specific persistence & autorun markers
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "StartupFolder", "RunOnce", "IFEO",

    # networking protocols / ports / C2 phrases
    "C2", "command and control", "callback", "reverse shell", "bind shell", "connectback", "beacon",

    # common short-coded obfuscation fragments
    "\\x00\\x01\\x02", "\\x90\\x90\\x90", "\\xDE\\xAD\\xBE\\xEF", "\\xCC\\xCC", "\\xff\\xd9",  # ff d9 = JPEG EOF
    "\\x89PNG", "\\x50\\x4B\\x03\\x04",  # PNG, ZIP

    # archive-in-image markers / nested archive names
    "embedded.zip", "embedded.rar", "inner.zip", "payload.zip", "archive.zip", "vbaProject", "word/vbaProject.bin",

    # common remote control / RAT names & terms (generic)
    "rat", "reverse_tcp", "meterpreter", "shellcode", "bind_tcp", "nc -e", "netcat", "socat",

    # suspicious MIME / content-range clues
    "application/octet-stream", "application/x-msdownload", "application/zip",
    "Content-Disposition:", "filename=", "Content-Transfer-Encoding:", "base64",

    # HTTP markers used by exfil / C2
    "/api/", "/upload", "/submit", "/data", "/report", "/beacon", "User-Agent:", "Referer:", "Authorization:",

    # more generic obfuscation / unusual patterns
    "String.fromCharCode", "String.fromCharCodes", "unescape(", "escape(", "atob(", "btoa(",

    # signs of multi-part or concatenated payloads
    "--boundary", "Content-Type: multipart", "Content-Encoding: gzip", "PKZIP", "ZIP64",

    # hints of stego tools and forensic artifacts
    "steghide", "steghide extract", "outguess", "openstego", "steghide", "silentink", "stegextract",

    # common C/C++ style indicators embedded as text
    "printf(", "fwrite(", "fopen(", "CreateFileA", "WriteFile", "ReadFile", "LoadLibraryA"
],


    "doc": [
        # --- Macro autorun ---
        "Sub AutoOpen()", "Document_Open", "AutoExec", "Auto_Close", "Document_Close",
        "Workbook_Open", "Presentation_Open", "ThisDocument", "NormalTemplate", "GlobalMacros",
        
        # --- Object creation ---
        "Shell", "CreateObject", "WScript.Shell", "FileSystemObject", "ADODB.Stream", "MSXML2.XMLHTTP",
        "WinHttp.WinHttpRequest", "Application.Run", "Application.OnTime", "VBProject", "VBComponents",
        
        # --- File actions ---
        "OpenTextFile", "SaveAs", "WriteLine", "AppendText", "Close", "Kill", "Dir(", "FileCopy",
        
        # --- Network actions ---
        "URLDownloadToFile", "XMLHTTP", "ServerXMLHTTP", "WinInet", "Environ(", "SendKeys",
        
        # --- Persistence ---
        "Registry", "RegWrite", "RegRead", "Startup", "AutoUpdate", "RunOnce",
        
        # --- Suspicious strings ---
        "Password", "Username", "Login", "Bank", "Credit Card", "OTP", "Secret", "HiddenSheet"
    ],

    "txt": [
        "keystroke", "logging keys", "keyboard capture", "password", "sensitive", "creds", "credentials",
        "logfile", "append", "Key Pressed", "username=", "password=", "Login Attempt", "typed:",
        "captured:", "clipboard", "credit card", "ssn", "bank", "otp", "hidden logs", "stealth",
        "data dump", "confidential", "PIN", "Account", "Session", "Cookies", "browser history",
        "http request", "ftp upload", "smtp send", "mail log", "shadow copy", "malware report",
        "captured keystrokes", "window focus", "foreground app", "chrome", "firefox", "edge",
        "sql", "injection", "payload", "shellcode", "cmdline", "powershell", "exfil"
    ],

    "pdf": [
    # JavaScript & PDF-specific patterns (keep old ones)
    "JavaScript", "/JS", "/OpenAction", "/AA", "this.exportDataObject", "util.printf", 
    "app.launchURL", "eval(", "Function(", "unescape(", "/AcroForm", "/RichMedia", 
    "getAnnots", "Collab.collectEmailInfo", "/Launch", "/SubmitForm", "app.mailMsg", 
    "xfa.host", "importDataObject", "/EmbeddedFile", "Doc.getField", "event.target", 
    "app.execMenuItem", "/GoToE", "/GoToR", "/Action", "/URI", "launchURL", "submitForm", 
    "getPageNumWords", "getPageNthWord", "app.setTimeOut", "app.clearTimeOut", "/Names", 
    "/JavaScript", "xfa", "this.getField", "xfa.connectionSet", "SOAP.connect", "xfa.form",

    # Python keylogger embedded keywords
    "pynput", "keyboard", "Key", "Listener", "KeyCode", "from pynput import keyboard",
    "threading", "datetime", "ImageGrab", "requests", "winreg", "os", "sys",
    "bot_token", "chat_id", "log1", "log2", "ss_file", "screenshot", "time_window", 
    "ss_interval", "exit_flag", "is_active", "active_log", "lock", "key_combo",
    "current_keys", "send_message", "send_log_content", "rotate_log", "on_press", 
    "on_release", "take_screenshot", "watch_telegram", "listener.start", "listener.join",
    "os._exit", "threading.Timer", "threading.Thread", "requests.post", "open(", "read(", "write("
],

    "msi" :  [
    # MSI core tables / installer concepts
    "CustomAction", "CustomActionData", "InstallExecuteSequence", "InstallUISequence",
    "Binary", "File", "Component", "Feature", "Directory", "Property", "Registry",
    "Shortcut", "CreateFolder", "RemoveFile", "ServiceInstall", "ServiceControl",
    "MsiInstallProduct", "MsiConfigureProduct", "MsiSetProperty", "MsiAdvertiseProduct",
    "MsiPublishComponents", "ComponentId", "FeatureId", "FileKey", "FileName",

    # msiexec and install switches
    "msiexec", "msiexec.exe", "/i ", "/x ", "/qn", "/quiet", "/passive", "/norestart",
    "/log ", "/l*v", "/silent", "REBOOT=",

    # custom action execution types & helpers
    "CAQuietExec", "CAQuietExec64", "Deferred", "Immediate", "Commit", "Rollback",
    "Type 18", "Type 34", "ExeCommand", "InstallExecute", "InstallFinalize",
    "InstallValidate", "LaunchCondition", "Condition",

    # embedded binary / cabinet / payload indicators
    "MZ", "PK\x03\x04", "PK", "This program cannot be run", "CAB", "CABinet",
    "Rar!", "7z", "gzip", "BZh", "payload", "dropper", "stager", "agent.exe",

    # scripting / embedded script markers
    "VBScript", "JScript", "WScript.Shell", "WScript.Echo", "cscript.exe", "wscript.exe",
    "PowerShell", "-EncodedCommand", "IEX", "Invoke-Expression", "powershell.exe",
    "mshta", "ScriptText", "ScriptStream", "ScriptType", "Execute(", "eval(", "exec(",

    # installer tool / builder fingerprints
    "InstallShield", "WiX", "WixToolset", "dark.exe", "candle.exe", "light.exe",
    "Advanced Installer", "NSIS", "Inno Setup", "InnoSetup", "MSI Wrapper", "ORCA",
    "MSM", "MST", "Transform", "MergeModule", "InstallScript", "Wise", "InstallAnywhere",

    # actions that invoke external processes
    "ShellExecute", "CreateProcess", "Run", "Exec", "Launch", "SilentInstall",
    "StartProcess", "ProcessPath", "CmdLine", "cmd.exe", "powershell -", "rundll32.exe",

    # persistence & autorun patterns
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "RunOnce", "StartupFolder", "RegisterService", "ServiceInstall", "sc create",
    "sc start", "reg add", "reg import", "IFEO", "Image File Execution Options",

    # registry / file operations strings
    "WriteRegistryValues", "RemoveRegistry", "WriteIniValues", "CreateFolder",
    "RemoveFolder", "CopyFile", "MoveFile", "DeleteFile", "ShortcutProperty", "Icon",

    # network / exfil / C2 strings
    "http://", "https://", "ftp://", "socket", "connect(", "send(", "recv(",
    "upload", "download", "URLDownloadToFile", "WinHttp", "MSXML2.XMLHTTP", "ADODB.Stream",

    # certificate / signing / trust indications
    "DigitalSignature", "Certificate", "SignTool", "Authenticode", "SHA1", "SHA256",
    "Signer", "Timestamp", "Catalog", "TrustedPublisher", "WinVerifyTrust",

    # packing / obfuscation / encoders often used in installers
    "Base64", "base64decode", "xor", "rot13", "obfuscate", "encrypt", "decrypt",
    "UPX", "Themida", "VMProtect", "ASPack", "NSIS", "SevenZip", "7zSFX",

    # common filenames inside installers
    "setup.exe", "installer.exe", "uninstall.exe", "install.exe", "setup.msi",
    "payload.exe", "dropper.exe", "agent.dll", "service.dll", "update.exe",

    # MSI internal table names often abused
    "CustomActionTable", "BinaryTable", "FileTable", "ComponentTable", "RegistryTable",
    "ShortcutTable", "ControlEvent", "Dialog", "Control", "ControlEvent", "PublishComponent",

    # strings indicating post-install scripts or commands
    "PostInstall", "PostInstallAction", "RunAfterInstall", "ExecuteAction",
    "OnInstall", "AfterInstall", "DoExecute", "ExecuteSequence", "InstallExecute",

    # heuristics / size / entropy hints (text markers)
    "base64,", "AAAA", "====", "-----BEGIN", "-----END", "BEGIN CERTIFICATE",
    "BEGIN RSA PRIVATE KEY", "randomdata", "verylong", "encrypted", "blob",

    # flags that indicate external processes / elevated execution
    "RequireAdministrator", "ALLUSERS=1", "Elevate", "UAC", "RunAs", "Impersonate",
    "MSIINSTALLPERUSER", "MSIINSTALLPERALLUSERS",

    # common commands used inside CustomAction to drop/run payloads
    "msiexec /i", "cmd /c", "start /wait", "start \"\"", "regsvr32 /s", "rundll32 ",
    "schtasks /create", "schtasks /run", "sc create", "sc start", "sc stop",

    # installer behavior and messages that could hide actions
    "InstallShield Silent", "QuietInstall", "SilentMode", "NoReboot", "Suppress", "SuppressModal",
    "DisplayNotInstalled", "ActionText", "Icon_", "Advertise", "Patch",

    # MSI-related tools & artifacts often left by builders
    "WixBundle", "Burn", "Bootstrapper", "SetupBootstrapper", "BootstrapperApplication",
    "PatchPackage", "PatchFiles", "CompanionFile", "EmbeddedCabinet", "CABFILE",

    # command patterns that indicate execution of scripts
    "vbscript", "jScript", "vbs", "js", ".vbs", ".js", ".ps1", ".bat", ".cmd",

    # strings used for installer logging / uninstall tracking
    "ARPINSTALLLOCATION", "ARPINSTALLSIZE", "ARPNAME", "ARPURLINFOABOUT", "ARPCOMMENTS",
    "HelpLink", "Readme", "InstallLog", "LogFile", "MsiLog",

    # generic packer / crypter / malware terms that may appear inside MSI bytes/text
    "trojan", "backdoor", "ransom", "keylogger", "spy", "spyware", "loader", "stager",

    # more low-level markers / signatures that could indicate embedded binaries
    "PE\0\0", "IMAGE_NT_HEADERS", "IMAGE_SECTION_HEADER", "MZ!", "MZ\x90", "DOS Header",

    # transform / merge-related
    ".mst", "Transform", "MergeModule", ".msm", "PatchSequence", "UpgradeCode", "ProductCode",

    # indicators of obfuscated command lines inside actions
    "%TEMP%", "%APPDATA%", "%PROGRAMFILES%", "%SYSTEMROOT%", "%WINDIR%", "%COMMONPROGRAMFILES%",

    # misc red flags often present in malicious installers
    "downloadandexecute", "drop and execute", "extractandrun", "extract here", "execute payload",
    "silent drop", "run hidden", "hide window", "no console", "no output", "background task"
]
}



BEHAVIOR_PATTERNS = [
    # --- Network exfiltration ---
    r"(requests|socket|ftp|smtplib|urllib|http\.client|ftplib|telnetlib|websocket|aiohttp|httpx)",

    # --- Encryption / encoding ---
    r"(base64|fernet|cryptography|AES|RSA|xor|binascii|hashlib|md5|sha1|sha256|rot13)",

    # --- Office macros / automation ---
    r"(Sub AutoOpen\(|Document_Open|AutoExec|Auto_Close|Workbook_Open|VBProject|VBComponents|WScript\.Shell|CreateObject)",

    # --- Keyboard & mouse hooks ---
    r"(SetWindowsHookEx|GetAsyncKeyState|keybd_event|SendInput|MapVirtualKey|GetKeyState|WH_KEYBOARD|WH_KEYBOARD_LL|WH_GETMESSAGE)",

    # --- Hook management ---
    r"(CallNextHookEx|UnhookWindowsHookEx)",

    # --- Window spying ---
    r"(GetForegroundWindow|GetWindowText|FindWindow|GetCursorPos|ShowWindow)",

    # --- File logging ---
    r"(CreateFileA|WriteFile|ReadFile|fopen|fwrite|fprintf|ofstream|logfile|append)",

    # --- Sandbox evasion / anti-debug ---
    r"(Sleep\([0-9]{4,}\)|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString)",

    # --- COM automation abuse ---
    r"(pythoncom|win32com|ShellExecute|ActiveXObject|MSXML2\.XMLHTTP|ADODB\.Stream)",

    # --- Python libraries (malware/keylogger) ---
    r"(pynput|keyboard|mouse|pyHook|pyxhook|pyautogui|pywin32)",

    # --- Suspicious logging & persistence ---
    r"(logging\.basicConfig|open\(.*,'a?'\)|rotatingfilehandler|os\.startfile|winreg|RunOnce|Startup)",

    # --- Clipboard spying ---
    r"(pyperclip|clipboard|GetClipboardData|OpenClipboard|EmptyClipboard)",

    # --- Process execution / persistence ---
    r"(subprocess\.Popen|CreateProcessA|WinExec|ShellExecuteA|powershell\.exe|cmd\.exe|schtasks|reg add)",

    # --- Network APIs (Win32) ---
    r"(InternetOpenA|InternetConnectA|HttpOpenRequestA|HttpSendRequestA|InternetReadFile|URLDownloadToFileA)",

    # --- Sensitive data capture ---
    r"(username=|password=|otp|credit card|bank|ssn|cookies|session|clipboard)"
]