#!/usr/bin/env python3
"""
Sentinel360 – Instalador de serviço do SO
Linux: cria unit file do systemd
Windows: registra serviço via pywin32 (ou sc.exe)
macOS: cria LaunchDaemon plist
"""
import os
import sys
import json
import platform
import subprocess
from pathlib import Path

AGENT_BIN = sys.executable.replace("python", "s360-agent") if "python" in sys.executable else "s360-agent"

# ─── Linux (systemd) ─────────────────────────────────────────────────────────

SYSTEMD_UNIT = """\
[Unit]
Description=Sentinel360 Remote Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User={user}
ExecStart={bin} daemon
Restart=always
RestartSec=60
StandardOutput=journal
StandardError=journal
Environment=HOME={home}

[Install]
WantedBy=multi-user.target
"""

def install_linux():
    user    = os.environ.get("USER", "root")
    home    = Path.home()
    unit    = SYSTEMD_UNIT.format(user=user, bin=AGENT_BIN, home=home)
    path    = Path("/etc/systemd/system/sentinel360.service")

    if os.geteuid() != 0:
        print("⚠ Instalação do serviço systemd requer sudo.")
        print(f"\nCopie manualmente:\n{unit}\n→ {path}")
        return

    path.write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "sentinel360"], check=True)
    subprocess.run(["systemctl", "start",  "sentinel360"], check=True)
    print("✅ Serviço sentinel360 instalado e iniciado.")
    print("   Verifique: journalctl -u sentinel360 -f")


# ─── macOS (launchd) ─────────────────────────────────────────────────────────

LAUNCHD_PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinel360.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{home}/.sentinel360/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{home}/.sentinel360/stderr.log</string>
</dict>
</plist>
"""

def install_macos():
    home  = Path.home()
    plist = LAUNCHD_PLIST.format(bin=AGENT_BIN, home=home)
    path  = home / "Library/LaunchAgents/com.sentinel360.agent.plist"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plist)
    subprocess.run(["launchctl", "load", "-w", str(path)], check=True)
    print(f"✅ LaunchAgent instalado em {path}")
    print("   Verifique: tail -f ~/.sentinel360/stdout.log")


# ─── Windows ──────────────────────────────────────────────────────────────────

WINDOWS_SERVICE = '''\
"""Sentinel360 Windows Service wrapper."""
import sys
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import asyncio
from agent import daemon_loop, load_config

class Sentinel360Service(win32serviceutil.ServiceFramework):
    _svc_name_        = "Sentinel360"
    _svc_display_name_ = "Sentinel360 Remote Agent"
    _svc_description_  = "Varredura de riscos e PII – Sentinel360 Cyber Defense"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        cfg = load_config()
        asyncio.run(daemon_loop(cfg))

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(Sentinel360Service)
'''

def install_windows():
    svc_path = Path.home() / ".sentinel360" / "windows_service.py"
    svc_path.parent.mkdir(parents=True, exist_ok=True)
    svc_path.write_text(WINDOWS_SERVICE)

    print("Para instalar o serviço Windows, execute como Administrador:")
    print(f"  python {svc_path} install")
    print(f"  python {svc_path} start")
    print()
    print("Dependências necessárias:")
    print("  pip install pywin32")


# ─── Entrypoint ──────────────────────────────────────────────────────────────

def main():
    system = platform.system()
    print(f"[Sentinel360] Detectado: {system}")

    if system == "Linux":
        install_linux()
    elif system == "Darwin":
        install_macos()
    elif system == "Windows":
        install_windows()
    else:
        print(f"SO não suportado automaticamente: {system}")
        print("Use 's360-agent daemon' manualmente.")


if __name__ == "__main__":
    main()
