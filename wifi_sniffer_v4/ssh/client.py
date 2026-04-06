"""
SSH Client v4
=============
Thread-safe SSH client using semaphore for controlled concurrency.
No paramiko — uses system OpenSSH only.

Improvements over v3:
- Semaphore (N concurrent) instead of mutex (1 at a time)
- SSH availability pre-check on init
- Cleaner error typing
"""

import logging
import os
import shutil
import subprocess
import threading
from typing import Optional, Tuple

from ..config import (
    OPENWRT_HOST, OPENWRT_USER,
    SSH_KEY_PATH, SSH_PORT,
    SSH_CONNECT_TIMEOUT, SSH_COMMAND_TIMEOUT,
    SSH_MAX_CONCURRENT,
)
from ..utils import get_subprocess_startupinfo

logger = logging.getLogger(__name__)


class SSHNotAvailableError(Exception):
    """Raised when ssh executable cannot be found."""


class SSHClient:
    """
    Thread-safe SSH client for command execution on OpenWrt.
    Uses a semaphore to allow up to SSH_MAX_CONCURRENT parallel commands.
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
        self._startupinfo = get_subprocess_startupinfo()
        self._semaphore = threading.Semaphore(SSH_MAX_CONCURRENT)
        self._ssh_available = False

        self._find_ssh_executable()
        self._ssh_available = self._check_ssh_available()

        self._initialized = True
        logger.info("SSHClient ready — ssh=%s available=%s concurrency=%d",
                     self._ssh_exe, self._ssh_available, SSH_MAX_CONCURRENT)

    # ------------------------------------------------------------------
    # Discovery & validation
    # ------------------------------------------------------------------

    def _find_ssh_executable(self) -> str:
        if self._ssh_exe:
            return self._ssh_exe

        path = shutil.which("ssh")
        if path:
            self._ssh_exe = path
            return self._ssh_exe

        # Windows-specific fallback paths
        candidates = [
            r"C:\Windows\System32\OpenSSH\ssh.exe",
            r"C:\Program Files\OpenSSH\ssh.exe",
            r"C:\Program Files (x86)\OpenSSH\ssh.exe",
        ]
        username = os.environ.get("USERNAME", "")
        if username:
            candidates.append(
                rf"C:\Users\{username}\AppData\Local\Microsoft\WindowsApps\ssh.exe"
            )
        for p in candidates:
            if os.path.exists(p):
                self._ssh_exe = p
                return self._ssh_exe

        self._ssh_exe = "ssh"
        return self._ssh_exe

    def _check_ssh_available(self) -> bool:
        """Verify that the ssh binary actually runs."""
        try:
            result = subprocess.run(
                [self._ssh_exe, "-V"],
                capture_output=True, text=True, timeout=5,
                startupinfo=self._startupinfo,
            )
            # ssh -V prints to stderr
            version_str = (result.stderr or result.stdout).strip()
            logger.info("SSH version: %s", version_str)
            return True
        except Exception as e:
            logger.error("SSH not available: %s", e)
            return False

    @property
    def is_available(self) -> bool:
        return self._ssh_available

    # ------------------------------------------------------------------
    # Command building
    # ------------------------------------------------------------------

    def _build_ssh_args(self, timeout: Optional[int] = None,
                        batch_mode: bool = False) -> list:
        args = [
            self._ssh_exe,
            "-o", "StrictHostKeyChecking=no",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PubkeyAuthentication=yes",
        ]
        if timeout is not None:
            args += ["-o", f"ConnectTimeout={timeout}"]
        if batch_mode:
            args += ["-o", "BatchMode=yes"]
        if SSH_PORT != 22:
            args += ["-p", str(SSH_PORT)]
        if SSH_KEY_PATH:
            args += ["-i", SSH_KEY_PATH]
        args.append(f"{OPENWRT_USER}@{OPENWRT_HOST}")
        return args

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, command: str,
                timeout: int = SSH_COMMAND_TIMEOUT) -> Tuple[bool, str, str]:
        """
        Execute *command* on the remote host.
        Returns (success, stdout, stderr).
        Uses semaphore to allow controlled concurrency.
        """
        if not self._ssh_available:
            return False, "", "SSH is not available on this system"

        ssh_cmd = self._build_ssh_args(timeout=SSH_CONNECT_TIMEOUT)
        ssh_cmd.append(command)

        # Semaphore: allows SSH_MAX_CONCURRENT parallel commands
        with self._semaphore:
            try:
                result = subprocess.run(
                    ssh_cmd,
                    capture_output=True, text=True,
                    timeout=timeout + 5,
                    startupinfo=self._startupinfo,
                )
                return result.returncode == 0, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                logger.warning("SSH timeout (%ds): %s", timeout, command[:80])
                return False, "", "Command timeout"
            except Exception as e:
                logger.debug("SSH execute error: %s", e)
                return False, "", str(e)

    def execute_background(self, command: str) -> Optional[subprocess.Popen]:
        """Start *command* as a background SSH process.
        NOTE: Acquires one semaphore slot — caller must call
        release_background() when the process terminates.
        """
        if not self._ssh_available:
            return None

        # Acquire a concurrency slot (non-blocking check first)
        if not self._semaphore.acquire(timeout=SSH_CONNECT_TIMEOUT):
            logger.warning("Background SSH: semaphore timeout, too many concurrent connections")
            return None

        ssh_cmd = self._build_ssh_args(timeout=SSH_CONNECT_TIMEOUT)
        ssh_cmd.append(command)
        try:
            return subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                startupinfo=self._startupinfo,
            )
        except Exception as e:
            self._semaphore.release()  # release on failure
            logger.error("Background SSH failed: %s", e)
            return None

    def release_background(self):
        """Release a semaphore slot after a background process finishes."""
        self._semaphore.release()

    def download_via_cat(self, remote_path: str, local_path: str) -> bool:
        """Download remote file by piping ``cat`` over SSH."""
        if not self._ssh_available:
            return False

        ssh_cmd = self._build_ssh_args(timeout=SSH_CONNECT_TIMEOUT)
        ssh_cmd.append(f"cat {remote_path}")

        # Ensure download directory exists
        local_dir = os.path.dirname(local_path)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

        with self._semaphore:
            try:
                logger.info("Downloading %s -> %s", remote_path, local_path)
                with open(local_path, "wb") as fh:
                    result = subprocess.run(
                        ssh_cmd,
                        stdout=fh,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL,
                        timeout=120,
                        startupinfo=self._startupinfo,
                    )
                if result.returncode == 0 and os.path.exists(local_path):
                    size = os.path.getsize(local_path)
                    logger.info("Download OK: %s bytes", f"{size:,}")
                    return size > 0

                # stderr is bytes here (stdout piped to binary file)
                stderr_msg = ""
                if result.stderr:
                    stderr_msg = result.stderr.decode(errors="replace") if isinstance(result.stderr, bytes) else str(result.stderr)
                logger.warning("Download failed: rc=%d %s", result.returncode, stderr_msg)
                return False
            except subprocess.TimeoutExpired:
                logger.warning("Download timeout (120s): %s", remote_path)
                return False
            except Exception as e:
                logger.error("Download error: %s", e)
                return False

    def test_connection(self) -> bool:
        """Quick connectivity test."""
        ok, stdout, _ = self.execute("echo connected", timeout=10)
        return ok and "connected" in stdout


# Global singleton
ssh_client = SSHClient()
