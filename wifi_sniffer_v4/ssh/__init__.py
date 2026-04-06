"""
SSH package – exposes convenience functions.
"""

from .client import SSHClient, ssh_client

# Convenience wrappers so services don't import the singleton directly.

def run_ssh_command(command: str, timeout: int = 30):
    """Execute *command* on OpenWrt. Returns (ok, stdout, stderr)."""
    return ssh_client.execute(command, timeout=timeout)


def download_file(remote_path: str, local_path: str) -> bool:
    """Download a file from OpenWrt via SSH cat pipe."""
    return ssh_client.download_via_cat(remote_path, local_path)


__all__ = ["ssh_client", "run_ssh_command", "download_file", "SSHClient"]
