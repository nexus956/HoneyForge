"""Decoy services shipped with HoneyForge."""

from .base import BaseHoneyService
from .ftp import FtpHoneyService
from .http import HttpHoneyService
from .ssh import SshHoneyService
from .telnet import TelnetHoneyService

__all__ = [
    "BaseHoneyService",
    "FtpHoneyService",
    "HttpHoneyService",
    "SshHoneyService",
    "TelnetHoneyService",
]

SERVICE_CLASSES = {
    "http": HttpHoneyService,
    "ssh": SshHoneyService,
    "telnet": TelnetHoneyService,
    "ftp": FtpHoneyService,
}
