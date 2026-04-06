"""
SSH Module
==========
SSH connection management and command execution.
"""

from .client import SSHClient, SSHError, ssh_client
from .commands import run_ssh_command, run_ssh_command_background, download_file

__all__ = [
    "SSHClient",
    "SSHError",
    "ssh_client",
    "run_ssh_command",
    "run_ssh_command_background",
    "download_file",
]
