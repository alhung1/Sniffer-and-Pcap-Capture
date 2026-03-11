"""
SSH Commands
============
Thin convenience wrappers over the SSHClient singleton.
"""

from typing import Tuple, Optional
import subprocess
from .client import ssh_client


def run_ssh_command(command: str, timeout: int = 30) -> Tuple[bool, str, str]:
    """Execute *command* on OpenWrt; returns ``(success, stdout, stderr)``."""
    return ssh_client.execute(command, timeout)


def run_ssh_command_background(command: str) -> Optional[subprocess.Popen]:
    """Start *command* in the background; returns the Popen handle."""
    return ssh_client.execute_background(command)


def download_file(remote_path: str, local_path: str) -> bool:
    """Download *remote_path* via SSH cat pipe to *local_path*."""
    return ssh_client.download_via_cat(remote_path, local_path)


def test_ssh_connection() -> bool:
    return ssh_client.test_connection()
