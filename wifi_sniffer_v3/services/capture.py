"""
Capture Service
===============
Manages WiFi packet capture sessions (start / stop / monitor).
"""

import logging
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from ..config import MONITOR_INTERVAL, MONITOR_ERROR_THRESHOLD
from ..ssh import run_ssh_command
from .file_download import FileDownloader

logger = logging.getLogger(__name__)


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

        self._status: Dict[str, Dict[str, Any]] = {
            "2G": {"running": False, "start_time": None, "packets": 0},
            "5G": {"running": False, "start_time": None, "packets": 0},
            "6G": {"running": False, "start_time": None, "packets": 0},
        }
        self._status_lock = threading.Lock()
        self._socketio = None

        self.file_split_config: Dict[str, Any] = {
            "enabled": False,
            "size_mb": 200,
        }

        self._monitor_error_count: Dict[str, int] = {"2G": 0, "5G": 0, "6G": 0}
        self._monitor_last_error: Dict[str, Optional[str]] = {"2G": None, "5G": None, "6G": None}

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
            except Exception as e:
                logger.debug("Broadcast error: %s", e)

    # ------------------------------------------------------------------
    # Status queries
    # ------------------------------------------------------------------

    def get_status(self, band: str) -> Dict[str, Any]:
        with self._status_lock:
            st = self._status[band].copy()
            if st["running"] and st["start_time"]:
                secs = int((datetime.now() - st["start_time"]).total_seconds())
                m, s = divmod(secs, 60)
                st["duration"] = f"{m:02d}:{s:02d}"
            else:
                st["duration"] = None
            return st

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        return {b: self.get_status(b) for b in ("2G", "5G", "6G")}

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_remote_processes(self) -> Tuple[bool, str]:
        """Kill stale tcpdump and remove temp pcap files."""
        try:
            logger.info("Cleaning up stale tcpdump processes...")
            ok, stdout, stderr = run_ssh_command(
                "killall tcpdump 2>/dev/null; echo 'CLEANUP_DONE'", timeout=10,
            )
            if ok and "CLEANUP_DONE" in stdout:
                run_ssh_command(
                    "rm -f /tmp/*.pcap /tmp/*.pcap[0-9]* 2>/dev/null", timeout=10,
                )
                logger.info("Cleanup completed")
                return True, "Cleanup completed"
            logger.warning("Cleanup command returned: %s %s", stdout, stderr)
            return False, f"Cleanup failed: {stderr or stdout}"
        except Exception as e:
            logger.error("Cleanup error: %s", e)
            return False, f"Cleanup error: {e}"

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------

    def start_capture(self, band: str, auto_sync_time: bool = True) -> Tuple[bool, str]:
        interface = self._iface_svc.interfaces.get(band)
        if not interface:
            return False, f"Unknown band: {band}"

        with self._status_lock:
            if self._status[band]["running"]:
                return False, f"{band} capture already running"

        try:
            if auto_sync_time:
                others_running = any(
                    self._status[b]["running"] for b in ("2G", "5G", "6G") if b != band
                )
                if not others_running:
                    logger.info("Syncing time before %s capture", band)
                    self._time_svc.sync_time()

            remote_path = f"/tmp/{band}.pcap"

            if self.file_split_config["enabled"]:
                size_mb = self.file_split_config["size_mb"]
                tcpdump = f"tcpdump -i {interface} -U -s0 -w {remote_path} -C {size_mb}"
            else:
                tcpdump = f"tcpdump -i {interface} -U -s0 -w {remote_path}"

            cmd = (
                f'PID=$(ps | grep "tcpdump -i {interface}" | grep -v grep | awk \'{{print $1}}\');'
                f' [ -n "$PID" ] && kill $PID 2>/dev/null;'
                f" rm -f {remote_path} {remote_path}[0-9]*;"
                f" ({tcpdump} &);"
                f" sleep 1;"
                f' ps | grep "tcpdump -i {interface}" | grep -v grep'
                f" && echo 'TCPDUMP_STARTED' || echo 'TCPDUMP_FAILED'"
            )

            ok, stdout, stderr = run_ssh_command(cmd, timeout=15)
            if not ok or "TCPDUMP_FAILED" in stdout:
                return False, f"Failed to start tcpdump: {stderr or stdout}"
            if "TCPDUMP_STARTED" not in stdout:
                return False, "tcpdump verification failed"

            with self._status_lock:
                self._status[band]["running"] = True
                self._status[band]["start_time"] = datetime.now()
                self._status[band]["packets"] = 0

            t = threading.Thread(target=self._monitor_capture, args=(band,), daemon=True)
            t.start()
            self._broadcast()
            return True, f"{band} capture started on {interface}"
        except Exception as e:
            return False, f"Error starting capture: {e}"

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------

    def stop_capture(self, band: str) -> Tuple[bool, str, Optional[str]]:
        with self._status_lock:
            if not self._status[band]["running"]:
                return False, f"{band} capture not running", None

        try:
            interface = self._iface_svc.interfaces.get(band)
            if not interface:
                return False, f"No interface for {band}", None

            logger.info("Stopping tcpdump on %s (%s)", interface, band)
            kill_cmd = (
                f"PID=$(ps | grep 'tcpdump -i {interface}' | grep -v grep | awk '{{print $1}}');"
                f' [ -n "$PID" ] && kill $PID 2>/dev/null || true'
            )
            run_ssh_command(kill_cmd, timeout=10)
            time.sleep(2)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ok, msg, path = self._downloader.download_pcap_files(band, timestamp)

            with self._status_lock:
                self._status[band]["running"] = False
                self._status[band]["start_time"] = None
            self._broadcast()
            return ok, msg, path
        except Exception as e:
            with self._status_lock:
                self._status[band]["running"] = False
                self._status[band]["start_time"] = None
            return False, f"Error stopping capture: {e}", None

    def stop_all_captures(self) -> Dict[str, Dict[str, Any]]:
        """Stop every band, kill all tcpdump, download any pcap files."""
        results: Dict[str, Dict[str, Any]] = {}

        logger.info("stop_all: killing all tcpdump on OpenWrt")
        ok, stdout, stderr = run_ssh_command(
            "killall tcpdump 2>/dev/null; echo KILL_DONE", timeout=15,
        )
        if not ok or "KILL_DONE" not in stdout:
            logger.error("stop_all: SSH failed – %s", stderr)
            for b in ("2G", "5G", "6G"):
                results[b] = {"success": False, "message": f"SSH error: {stderr or 'Cannot connect'}", "path": None}
            return results

        time.sleep(2)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for band in ("2G", "5G", "6G"):
            ok, msg, path = self._downloader.download_pcap_files(band, timestamp)
            results[band] = {"success": ok, "message": msg, "path": path}
            with self._status_lock:
                self._status[band]["running"] = False
                self._status[band]["start_time"] = None

        self._broadcast()
        logger.info("stop_all completed: %s", results)
        return results

    # ------------------------------------------------------------------
    # Monitor
    # ------------------------------------------------------------------

    def _monitor_capture(self, band: str):
        while self._status[band]["running"]:
            try:
                remote = f"/tmp/{band}.pcap"
                ok, stdout, stderr = run_ssh_command(
                    f"ls -la {remote} 2>/dev/null | awk '{{print $5}}'", timeout=8,
                )
                if ok and stdout.strip():
                    try:
                        size = int(stdout.strip())
                        with self._status_lock:
                            self._status[band]["packets"] = size // 100
                        self._monitor_error_count[band] = 0
                        self._monitor_last_error[band] = None
                    except ValueError:
                        pass
                else:
                    self._monitor_error_count[band] += 1
                    self._monitor_last_error[band] = stderr or "SSH command failed"
                    if self._monitor_error_count[band] == MONITOR_ERROR_THRESHOLD:
                        logger.warning("%s: monitor SSH errors (%dx)", band, MONITOR_ERROR_THRESHOLD)
            except Exception as e:
                self._monitor_error_count[band] += 1
                self._monitor_last_error[band] = str(e)
                if self._monitor_error_count[band] == MONITOR_ERROR_THRESHOLD:
                    logger.warning("%s: monitor exception (%dx): %s", band, MONITOR_ERROR_THRESHOLD, e)
            time.sleep(MONITOR_INTERVAL)
