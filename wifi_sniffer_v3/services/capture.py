"""
Capture Service
===============
Manages WiFi packet capture sessions (start / stop / monitor).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from ..config import MONITOR_ERROR_THRESHOLD, MONITOR_INTERVAL
from ..remote import (
    RemoteCommandError,
    build_capture_size_command,
    build_cleanup_stale_captures_command,
    build_start_capture_command,
    build_stop_capture_command,
    make_capture_paths,
    new_session_id,
    validate_band,
    validate_interface,
)
from ..ssh import run_ssh_command
from .file_download import FileDownloader

logger = logging.getLogger(__name__)


@dataclass
class CaptureBandState:
    running: bool = False
    start_time: Optional[datetime] = None
    estimated_packets: int = 0
    file_size_bytes: int = 0
    session_id: Optional[str] = None
    remote_pcap_path: Optional[str] = None
    remote_pid_path: Optional[str] = None
    pending_action: Optional[str] = None
    last_error: Optional[str] = None


class CaptureService:
    """
    Owns capture state for each band and delegates file download to
    ``FileDownloader``.

    Requires references to ``InterfaceService``, ``TimeSyncService``
    and ``WifiConfigService`` (for file-split config access).
    """

    def __init__(self, interface_service, time_sync_service, wifi_config_service):
        self._iface_svc = interface_service
        self._time_svc = time_sync_service
        self._wifi_svc = wifi_config_service
        self._downloader = FileDownloader()

        self._status = {
            "2G": CaptureBandState(),
            "5G": CaptureBandState(),
            "6G": CaptureBandState(),
        }
        self._status_lock = threading.Lock()
        self._socketio = None

        self.file_split_config: dict[str, Any] = {
            "enabled": False,
            "size_mb": 200,
        }

        self._monitor_error_count: dict[str, int] = {"2G": 0, "5G": 0, "6G": 0}
        self._monitor_last_error: dict[str, Optional[str]] = {"2G": None, "5G": None, "6G": None}

        self.last_connection_error: Optional[str] = None

    # ------------------------------------------------------------------
    # SocketIO integration
    # ------------------------------------------------------------------

    def set_socketio(self, sio):
        self._socketio = sio

    def _broadcast(self):
        if self._socketio:
            try:
                self._socketio.emit("status_update", self.get_all_status())
            except Exception as exc:
                logger.debug("Broadcast error: %s", exc)

    # ------------------------------------------------------------------
    # Status queries
    # ------------------------------------------------------------------

    def _snapshot_status(self, band: str, state: CaptureBandState) -> dict[str, Any]:
        status = {
            "running": state.running,
            "start_time": state.start_time,
            "packets": state.estimated_packets,
            "estimated_packets": state.estimated_packets,
            "file_size_bytes": state.file_size_bytes,
            "session_id": state.session_id,
            "pending_action": state.pending_action,
            "last_error": state.last_error,
        }
        if state.pending_action == "starting":
            status["state"] = "starting"
        elif state.pending_action == "stopping":
            status["state"] = "stopping"
        elif state.running:
            status["state"] = "running"
        else:
            status["state"] = "idle"

        if state.running and state.start_time:
            secs = int((datetime.now() - state.start_time).total_seconds())
            mins, secs = divmod(secs, 60)
            status["duration"] = f"{mins:02d}:{secs:02d}"
        else:
            status["duration"] = None
        return status

    def get_status(self, band: str) -> dict[str, Any]:
        normalized_band = validate_band(band)
        with self._status_lock:
            return self._snapshot_status(normalized_band, self._status[normalized_band])

    def get_all_status(self) -> dict[str, dict[str, Any]]:
        with self._status_lock:
            return {
                band: self._snapshot_status(band, state)
                for band, state in self._status.items()
            }

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_remote_processes(self) -> tuple[bool, str]:
        """Clean up only app-managed capture processes and capture files."""
        try:
            logger.info("Cleaning up stale app capture processes")
            ok, stdout, stderr = run_ssh_command(build_cleanup_stale_captures_command(), timeout=10)
            if ok and "CLEANUP_DONE" in stdout:
                logger.info("App capture cleanup completed")
                return True, "Cleanup completed"

            details = (stderr or stdout or "unknown error").strip()
            logger.warning("Cleanup command returned: %s", details)
            return False, f"Cleanup failed: {details}"
        except Exception as exc:
            logger.error("Cleanup error: %s", exc)
            return False, f"Cleanup error: {exc}"

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------

    def start_capture(self, band: str, auto_sync_time: bool = True) -> tuple[bool, str]:
        normalized_band = validate_band(band)
        interface = self._iface_svc.interfaces.get(normalized_band)
        if not interface:
            return False, f"Unknown band: {normalized_band}"

        try:
            validate_interface(interface)
        except RemoteCommandError as exc:
            return False, str(exc)

        session_id = new_session_id()
        paths = make_capture_paths(normalized_band, session_id)

        with self._status_lock:
            state = self._status[normalized_band]
            if state.running or state.pending_action:
                return False, f"{normalized_band} capture already running"
            state.pending_action = "starting"
            state.last_error = None
            state.session_id = session_id
            state.remote_pcap_path = paths.remote_pcap_path
            state.remote_pid_path = paths.remote_pid_path
            others_running = any(
                other.running
                for other_band, other in self._status.items()
                if other_band != normalized_band
            )

        try:
            if auto_sync_time and not others_running:
                logger.info("Syncing time before %s capture", normalized_band)
                self._time_svc.sync_time()

            split_size_mb = None
            if self.file_split_config["enabled"]:
                split_size_mb = self.file_split_config["size_mb"]

            command = build_start_capture_command(interface, paths, split_size_mb=split_size_mb)
            ok, stdout, stderr = run_ssh_command(command, timeout=15)
            if not ok or "TCPDUMP_FAILED" in stdout or "TCPDUMP_STARTED" not in stdout:
                details = (stderr or stdout or "verification failed").strip()
                self._mark_start_failed(normalized_band, details)
                return False, f"Failed to start tcpdump: {details}"

            with self._status_lock:
                state = self._status[normalized_band]
                state.running = True
                state.start_time = datetime.now()
                state.estimated_packets = 0
                state.file_size_bytes = 0
                state.pending_action = None
                state.last_error = None

            monitor = threading.Thread(
                target=self._monitor_capture,
                args=(normalized_band, session_id),
                daemon=True,
            )
            monitor.start()
            self._broadcast()
            return True, f"{normalized_band} capture started on {interface}"
        except Exception as exc:
            self._mark_start_failed(normalized_band, str(exc))
            return False, f"Error starting capture: {exc}"

    def _mark_start_failed(self, band: str, error_message: str):
        with self._status_lock:
            state = self._status[band]
            state.running = False
            state.start_time = None
            state.estimated_packets = 0
            state.file_size_bytes = 0
            state.pending_action = None
            state.last_error = error_message
            state.session_id = None
            state.remote_pcap_path = None
            state.remote_pid_path = None
        self._broadcast()

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------

    def stop_capture(self, band: str) -> tuple[bool, str, Optional[str]]:
        normalized_band = validate_band(band)
        with self._status_lock:
            state = self._status[normalized_band]
            if state.pending_action == "starting":
                return False, f"{normalized_band} capture is still starting", None
            if state.pending_action == "stopping":
                return False, f"{normalized_band} capture is already stopping", None
            if not state.running or not state.session_id:
                return False, f"{normalized_band} capture not running", None

            session_id = state.session_id
            state.pending_action = "stopping"
            state.last_error = None

        try:
            paths = make_capture_paths(normalized_band, session_id)
            logger.info("Stopping capture for %s (session=%s)", normalized_band, session_id)
            stop_ok, stop_stdout, stop_stderr = run_ssh_command(
                build_stop_capture_command(paths),
                timeout=10,
            )
            if not stop_ok:
                logger.warning(
                    "Stop command for %s reported an SSH issue: %s",
                    normalized_band,
                    stop_stderr or stop_stdout,
                )

            time.sleep(1)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ok, msg, path = self._downloader.download_pcap_files(
                normalized_band,
                timestamp,
                session_id,
            )
            self._clear_band_state(normalized_band)
            self._broadcast()
            return ok, msg, path
        except Exception as exc:
            self._clear_band_state(normalized_band, last_error=str(exc))
            self._broadcast()
            return False, f"Error stopping capture: {exc}", None

    def stop_all_captures(self) -> dict[str, dict[str, Any]]:
        """Stop all active sessions without touching unrelated tcpdump processes."""
        results: dict[str, dict[str, Any]] = {}
        for band in ("2G", "5G", "6G"):
            ok, msg, path = self.stop_capture(band)
            results[band] = {"success": ok, "message": msg, "path": path}
        logger.info("stop_all completed: %s", results)
        return results

    def _clear_band_state(self, band: str, last_error: Optional[str] = None):
        with self._status_lock:
            state = self._status[band]
            state.running = False
            state.start_time = None
            state.estimated_packets = 0
            state.file_size_bytes = 0
            state.pending_action = None
            state.last_error = last_error
            state.session_id = None
            state.remote_pcap_path = None
            state.remote_pid_path = None

    # ------------------------------------------------------------------
    # Monitor
    # ------------------------------------------------------------------

    def _monitor_capture(self, band: str, session_id: str):
        while True:
            with self._status_lock:
                state = self._status[band]
                if (
                    not state.running
                    or state.session_id != session_id
                    or state.pending_action == "stopping"
                ):
                    return

            try:
                paths = make_capture_paths(band, session_id)
                ok, stdout, stderr = run_ssh_command(build_capture_size_command(paths), timeout=8)
                if ok and stdout.strip():
                    try:
                        size = int(stdout.strip())
                    except ValueError:
                        logger.debug("%s: unexpected size payload %r", band, stdout)
                    else:
                        with self._status_lock:
                            state = self._status[band]
                            if state.session_id != session_id:
                                return
                            state.file_size_bytes = size
                            # Preserve the existing UI behavior, but expose it as an estimate.
                            state.estimated_packets = size // 100
                        self._monitor_error_count[band] = 0
                        self._monitor_last_error[band] = None
                else:
                    self._monitor_error_count[band] += 1
                    self._monitor_last_error[band] = stderr or "SSH command failed"
                    if self._monitor_error_count[band] == MONITOR_ERROR_THRESHOLD:
                        logger.warning("%s: monitor SSH errors (%dx)", band, MONITOR_ERROR_THRESHOLD)
            except Exception as exc:
                self._monitor_error_count[band] += 1
                self._monitor_last_error[band] = str(exc)
                if self._monitor_error_count[band] == MONITOR_ERROR_THRESHOLD:
                    logger.warning("%s: monitor exception (%dx): %s", band, MONITOR_ERROR_THRESHOLD, exc)

            time.sleep(MONITOR_INTERVAL)
