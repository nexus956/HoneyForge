"""Telnet decoy — a fake BusyBox shell on an IoT-style device.

Mirai-class worms enumerate Telnet, try a credential list, then drop a loader
(``wget http://…/bot.sh; sh``). This decoy walks the whole conversation:
login prompt, password prompt, and a believable BusyBox shell whose commands
are recorded verbatim before being answered with canned output.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from ..events import Event
from .base import BaseHoneyService, LineReader, clean_line

log = logging.getLogger("honeyforge.telnet")

MAX_COMMANDS = 500

FAKE_FILES: Dict[str, str] = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
    "/etc/shadow": "root:$1$abc123:0:0:99999:7:::\n",
    "/proc/cpuinfo": (
        "system type\t\t: MT7628\n"
        "machine\t\t\t: Unknown\n"
        "processor\t\t: 0\n"
        "cpu model\t\t: MIPS 24Kc V5.5\n"
        "BogoMIPS\t\t: 259.58\n"
    ),
    "/proc/meminfo": (
        "MemTotal:          61440 kB\n"
        "MemFree:           48892 kB\n"
    ),
}

FAKE_COMMANDS: Dict[str, str] = {
    "ls": "bin  dev  etc  lib  mnt  proc  root  sbin  tmp  usr  www",
    "busybox": "BusyBox v1.22.1 (2026-01-04 15:30:22 UTC) multi-call binary.",
    "uname -a": "Linux Router 3.4.113 #1 SMP Mon Jan 4 15:12:33 UTC 2026 mips GNU/Linux",
    "id": "uid=0(root) gid=0(root)",
    "ps": "  PID  Uid     Cmd\n    1  root    init\n   42  root    hostapd\n   77  root    telnetd",
    "ifconfig": (
        "eth0      Link encap:Ethernet  HWaddr AA:BB:CC:DD:EE:F0\n"
        "          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0"
    ),
    "cat /proc/mounts": "rootfs / rootfs rw 0 0\n",
    "which tftp": "/usr/bin/tftp",
    "which wget": "/usr/bin/wget",
}


class TelnetHoneyService(BaseHoneyService):
    """BusyBox-flavoured Telnet pot."""

    name = "telnet"

    def __init__(self, host: str, port: int, bus, banner: str = "", prompt: str = "# ") -> None:
        super().__init__(host, port, bus, service_name="telnet")
        self.welcome_banner = banner or (
            "BusyBox v1.22.1 (2026-01-04 15:30:22 UTC) built-in shell (ash)\n"
            "Enter 'help' for a list of built-in commands.\n"
        )
        self.prompt = prompt

    def handle_client(self, conn, addr) -> None:
        src_ip, src_port = addr
        reader = LineReader(conn)

        # Greeting in a single write so the banner and the first prompt reach
        # the client in one TCP segment, like a real telnetd.
        greeting = ("\r\n" + self.welcome_banner + "login: ")
        self.send(conn, greeting.encode("utf-8"))

        username = self._read_login_field(reader)
        if username is None:
            return
        self.send(conn, b"Password: ")
        password = self._read_login_field(reader)
        password = password if password is not None else ""

        self.publish(Event(
            type="login_attempt", src_ip=src_ip, src_port=src_port, service=self.service,
            details={"username": username, "password": password, "success": True,
                     "via": "telnet"},
        ))

        self.send(conn, ("\r\n" + self.prompt).encode())
        self.shell_loop(reader, conn, src_ip, src_port)

    # ---------------------------------------------------------------- shell

    def shell_loop(self, reader: LineReader, conn, src_ip: str, src_port: int) -> None:
        for _ in range(MAX_COMMANDS):
            raw = reader.readline()
            if raw is None:
                return
            command = clean_line(raw)
            if not command:
                self.send(conn, self.prompt.encode())
                continue
            self.publish(Event(type="command", src_ip=src_ip, src_port=src_port,
                               service=self.service,
                               details={"command": command, "protocol": "telnet"}))
            if command in ("exit", "logout", "quit"):
                self.send_line(conn, "Connection closed by foreign host.")
                return
            # Reply and prompt go out in a single write so prompt-paced clients
            # never see them split across TCP segments.
            self.send(conn, self._reply(command).encode("utf-8", errors="replace")
                      + self.prompt.encode())

    def _reply(self, command: str) -> str:
        head = command.split(" ", 1)[0]
        if command in FAKE_COMMANDS:
            return FAKE_COMMANDS[command] + "\n"
        if head == "cat":
            target = command.split(" ", 1)[1].strip() if " " in command else ""
            return (FAKE_FILES.get(target) or "cat: read error: No such file or directory") + "\n"
        if head == "echo":
            return command.split(" ", 1)[1].strip() + "\n" if " " in command else "\n"
        if head in ("cd", "rm", "mkdir", "touch", "chmod"):
            return ""
        if head in ("wget", "tftp", "curl", "ftpget"):
            # "Download" convincingly, then claim the tool is missing —
            # we never want to encourage follow-on exploitation attempts.
            return (f"Connecting to target\n"
                    f"sh: {head}: Permission denied\n")
        if head == "help":
            return ("Available commands: ls, cat, echo, ps, ifconfig, uname, id,\n"
                    "busybox, wget, tftp, cd, rm, exit\n")
        return f"sh: {head}: not found\n"

    def _read_login_field(self, reader: LineReader) -> Optional[str]:
        raw = reader.readline()
        if raw is None:
            return None
        return clean_line(raw)
