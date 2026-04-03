"""
Remote command helpers
======================
Centralizes validation, remote path generation, and shell-safe command
construction for OpenWrt capture operations.
"""

from __future__ import annotations

import re
import shlex
import uuid
from dataclasses import dataclass

from .config import APP_REMOTE_PREFIX

VALID_BANDS = frozenset({"2G", "5G", "6G"})
_INTERFACE_RE = re.compile(r"^ath[0-9]+$")
_SESSION_ID_RE = re.compile(r"^[a-z0-9]{6,32}$")


class RemoteCommandError(ValueError):
    """Raised when a band, interface, or remote path is invalid."""


@dataclass(frozen=True)
class RemoteCapturePaths:
    """Remote artifacts for a single capture session."""

    band: str
    session_id: str
    prefix: str
    base_dir: str = "/tmp"

    @property
    def base_name(self) -> str:
        return f"{self.prefix}_{self.band.lower()}_{self.session_id}.pcap"

    @property
    def remote_pcap_path(self) -> str:
        return f"{self.base_dir}/{self.base_name}"

    @property
    def remote_pid_name(self) -> str:
        return f"{self.prefix}_{self.band.lower()}_{self.session_id}.pid"

    @property
    def remote_pid_path(self) -> str:
        return f"{self.base_dir}/{self.remote_pid_name}"


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def validate_band(band: str) -> str:
    normalized = band.upper()
    if normalized not in VALID_BANDS:
        raise RemoteCommandError(f"Invalid band: {band}")
    return normalized


def validate_interface(interface: str) -> str:
    if not interface or not _INTERFACE_RE.fullmatch(interface):
        raise RemoteCommandError(f"Invalid interface name: {interface!r}")
    return interface


def new_session_id() -> str:
    return uuid.uuid4().hex[:12]


def make_capture_paths(band: str, session_id: str) -> RemoteCapturePaths:
    normalized_band = validate_band(band)
    if not session_id or not _SESSION_ID_RE.fullmatch(session_id):
        raise RemoteCommandError(f"Invalid session_id: {session_id!r}")
    return RemoteCapturePaths(
        band=normalized_band,
        session_id=session_id,
        prefix=APP_REMOTE_PREFIX,
    )


def _build_capture_file_match(paths: RemoteCapturePaths) -> str:
    base_name = paths.base_name
    split_pattern = f"{base_name}[0-9]*"
    return (
        f"find {shell_quote(paths.base_dir)} -maxdepth 1 -type f "
        f"\\( -name {shell_quote(base_name)} -o -name {shell_quote(split_pattern)} \\)"
    )


def build_start_capture_command(
    interface: str,
    paths: RemoteCapturePaths,
    split_size_mb: int | None = None,
) -> str:
    iface = validate_interface(interface)
    tcpdump_args = ["tcpdump", "-i", iface, "-U", "-s0", "-w", paths.remote_pcap_path]
    if split_size_mb is not None:
        tcpdump_args.extend(["-C", str(split_size_mb)])

    tcpdump_cmd = " ".join(shell_quote(arg) for arg in tcpdump_args)
    launcher_script = (
        f"{tcpdump_cmd} >/dev/null 2>&1 & "
        f"echo $! > {shell_quote(paths.remote_pid_path)}"
    )

    return " ; ".join([
        build_remove_capture_artifacts_command(paths),
        f"sh -c {shell_quote(launcher_script)}",
        "sleep 1",
        f'PID=$(cat {shell_quote(paths.remote_pid_path)} 2>/dev/null)',
        '[ -n "$PID" ] && kill -0 "$PID" 2>/dev/null && echo TCPDUMP_STARTED || echo TCPDUMP_FAILED',
    ])


def build_stop_capture_command(paths: RemoteCapturePaths) -> str:
    return " ; ".join([
        f'PID=$(cat {shell_quote(paths.remote_pid_path)} 2>/dev/null)',
        '[ -n "$PID" ] && kill "$PID" 2>/dev/null || true',
        f"rm -f {shell_quote(paths.remote_pid_path)}",
    ])


def build_list_capture_files_command(paths: RemoteCapturePaths) -> str:
    return f"{_build_capture_file_match(paths)} -print 2>/dev/null | sort"


def build_capture_size_command(paths: RemoteCapturePaths) -> str:
    return (
        f"{_build_capture_file_match(paths)} "
        "-exec ls -ln {} \\; 2>/dev/null | awk '{sum += $5} END {print sum+0}'"
    )


def build_remove_capture_artifacts_command(paths: RemoteCapturePaths) -> str:
    return " ; ".join([
        f"{_build_capture_file_match(paths)} -delete 2>/dev/null",
        f"rm -f {shell_quote(paths.remote_pid_path)}",
    ])


def build_cleanup_stale_captures_command() -> str:
    pid_pattern = f"{APP_REMOTE_PREFIX}_*.pid"
    pcap_pattern = f"{APP_REMOTE_PREFIX}_*.pcap*"

    return " ; ".join([
        (
            "find /tmp -maxdepth 1 -type f "
            f"-name {shell_quote(pid_pattern)} -print 2>/dev/null | "
            "while IFS= read -r pid_file; do "
            'PID=$(cat "$pid_file" 2>/dev/null); '
            '[ -n "$PID" ] && kill "$PID" 2>/dev/null || true; '
            'rm -f "$pid_file"; '
            "done"
        ),
        (
            "find /tmp -maxdepth 1 -type f "
            f"\\( -name {shell_quote(pid_pattern)} -o -name {shell_quote(pcap_pattern)} \\) "
            "-delete 2>/dev/null"
        ),
        "echo CLEANUP_DONE",
    ])
