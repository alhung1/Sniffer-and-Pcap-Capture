"""
SSH Client
==========
Reusable SSH client for executing commands on OpenWrt.
Uses Windows OpenSSH subprocess under the hood.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from typing import Optional

from ..config import CONFIG
from ..remote import shell_quote
from ..utils import get_subprocess_startupinfo

logger = logging.getLogger(__name__)


class SSHError(Exception):
    """Raised when an SSH operation fails."""


class SSHClient:
    """
    Thread-safe SSH client for command execution on OpenWrt.

    Uses subprocess + OpenSSH rather than paramiko for better
    compatibility with Windows built-in SSH.
    """

    _instance = None
    _init_lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._ssh_exe: Optional[str] = None
        self._pubkey_option: Optional[str] = None
        self._startupinfo = get_subprocess_startupinfo()
        self._command_lock = threading.Lock()

        self._find_ssh_executable()
        self._detect_pubkey_option()

        self._initialized = True
        logger.info("SSHClient initialised, ssh=%s", self._ssh_exe)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_ssh_executable(self) -> str:
        if self._ssh_exe:
            return self._ssh_exe

        ssh_path = shutil.which("ssh")
        if ssh_path:
            self._ssh_exe = ssh_path
            return self._ssh_exe

        candidates = [
            r"C:\Windows\System32\OpenSSH\ssh.exe",
            r"C:\Program Files\OpenSSH\ssh.exe",
            r"C:\Program Files (x86)\OpenSSH\ssh.exe",
            rf"C:\Users\{os.environ.get('USERNAME', '')}\AppData\Local\Microsoft\WindowsApps\ssh.exe",
        ]
        for path in candidates:
            if os.path.exists(path):
                self._ssh_exe = path
                return self._ssh_exe

        self._ssh_exe = "ssh"
        return self._ssh_exe

    def _detect_pubkey_option(self):
        if self._pubkey_option is not None:
            return

        for opt in ("PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes"):
            try:
                probe = subprocess.run(
                    [self._ssh_exe, "-G", "-o", f"{opt}=+ssh-rsa", "dummy"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    startupinfo=self._startupinfo,
                )
                if probe.returncode == 0:
                    self._pubkey_option = opt
                    return
            except Exception:
                continue

        self._pubkey_option = None

    def _build_ssh_args(self, timeout: Optional[int] = None, batch_mode: bool = False) -> list[str]:
        args = [
            self._ssh_exe,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "HostKeyAlgorithms=+ssh-rsa",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAuthentication=yes",
        ]
        if self._pubkey_option:
            args += ["-o", f"{self._pubkey_option}=+ssh-rsa"]
        if timeout is not None:
            args += ["-o", f"ConnectTimeout={timeout}"]
        if batch_mode:
            args += ["-o", "BatchMode=yes"]
        if CONFIG.ssh_port != 22:
            args += ["-p", str(CONFIG.ssh_port)]
        if CONFIG.ssh_key_path:
            args += ["-i", CONFIG.ssh_key_path]
        args.append(f"{CONFIG.openwrt_user}@{CONFIG.openwrt_host}")
        return args

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, command: str, timeout: int = CONFIG.ssh_command_timeout) -> tuple[bool, str, str]:
        """
        Execute *command* on the remote host.

        Returns ``(success, stdout, stderr)``.
        """
        ssh_cmd = self._build_ssh_args(timeout=CONFIG.ssh_connect_timeout)
        ssh_cmd.append(command)

        with self._command_lock:
            try:
                result = subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 5,
                    startupinfo=self._startupinfo,
                )
                ok = result.returncode == 0
                return ok, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                return False, "", "Command timeout"
            except Exception as exc:
                logger.debug("SSH execute error: %s", exc)
                return False, "", str(exc)

    def execute_background(self, command: str) -> Optional[subprocess.Popen]:
        """Start *command* as a background process and return the Popen handle."""
        ssh_cmd = self._build_ssh_args(timeout=CONFIG.ssh_connect_timeout)
        ssh_cmd.append(command)
        try:
            return subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                startupinfo=self._startupinfo,
            )
        except Exception as exc:
            logger.error("Failed to start background SSH command: %s", exc)
            return None

    def download_via_cat(self, remote_path: str, local_path: str) -> bool:
        """
        Download a remote file by piping ``cat <path>`` over SSH.

        Returns ``True`` when the file is written locally with size > 0.
        """
        ssh_cmd = self._build_ssh_args(timeout=CONFIG.ssh_connect_timeout)
        ssh_cmd.append(f"cat {shell_quote(remote_path)}")

        try:
            logger.info("Downloading %s -> %s", remote_path, local_path)
            with open(local_path, "wb") as handle:
                result = subprocess.run(
                    ssh_cmd,
                    stdout=handle,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    timeout=120,
                    startupinfo=self._startupinfo,
                )

            if result.returncode == 0 and os.path.exists(local_path):
                size = os.path.getsize(local_path)
                logger.info("Download OK: %d bytes", size)
                return size > 0

            stderr_msg = result.stderr.decode() if result.stderr else "Unknown error"
            logger.warning("Download failed: %s", stderr_msg)
            return False
        except Exception as exc:
            logger.error("Download error: %s", exc)
            return False

    def test_connection(self) -> bool:
        """Quick connectivity test."""
        ok, stdout, _ = self.execute("echo connected", timeout=10)
        return ok and "connected" in stdout


# Global singleton
ssh_client = SSHClient()
