"""
Capture Service
===============
Manages WiFi packet capture sessions (start / stop / monitor).
v4: Shows real file size instead of fake packet count.
"""

import logging
import re
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from ..config import MONITOR_INTERVAL, MONITOR_ERROR_THRESHOLD
from ..ssh import run_ssh_command
from .file_download import FileDownloader, _format_size

logger = logging.getLogger(__name__)

_SAFE_IFACE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,15}$")
_VALID_BANDS = {"2G", "5G", "6G"}


class CaptureService:
    """
    Owns capture state for each band.
    Delegates file download to FileDownloader.
    """

    def __init__(self, interface_service, time_sync_service, wifi_config_service):
        self._iface_svc = interface_service
        self._time_svc = time_sync_service
        self._wifi_svc = wifi_config_service
        self._downloader = FileDownloader()

        self._status: Dict[str, Dict[str, Any]] = {
            "2G": {"running": False, "start_time": None, "file_size": 0},
            "5G": {"running": False, "start_time": None, "file_size": 0},
            "6G": {"running": False, "start_time": None, "file_size": 0},
        }
        self._status_lock = threading.Lock()
        self._socketio = None

        self.file_split_config: Dict[str, Any] = {"enabled": False, "size_mb": 200}

        self._monitor_error_count: Dict[str, int] = {"2G": 0, "5G": 0, "6G": 0}
        self.last_connection_error: Optional[str] = None

        # v4: Restore file_split from persistent config
        self._load_saved_split_config()

    def _load_saved_split_config(self):
        from ..config import load_persistent_config
        data = load_persistent_config()
        saved = data.get("file_split")
        if saved and isinstance(saved, dict):
            self.file_split_config["enabled"] = bool(saved.get("enabled", False))
            self.file_split_config["size_mb"] = int(saved.get("size_mb", 200))
            logger.info("Restored file_split config: %s", self.file_split_config)

    def _save_split_config(self):
        from ..config import load_persistent_config, save_persistent_config
        data = load_persistent_config()
        data["file_split"] = dict(self.file_split_config)
        save_persistent_config(data)

    def update_file_split(self, enabled: Optional[bool] = None, size_mb: Optional[int] = None):
        """Update file split settings and persist."""
        if enabled is not None:
            self.file_split_config["enabled"] = enabled
        if size_mb is not None:
            self.file_split_config["size_mb"] = max(10, min(2000, size_mb))
        self._save_split_config()

    # ------------------------------------------------------------------
    # SocketIO
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
    # Status
    # ------------------------------------------------------------------

    def get_status(self, band: str) -> Dict[str, Any]:
        with self._status_lock:
            st = self._status[band].copy()
            if st["running"] and st["start_time"]:
                secs = int((datetime.now() - st["start_time"]).total_seconds())
                m, s = divmod(secs, 60)
                h, m = divmod(m, 60)
                st["duration"] = f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
            else:
                st["duration"] = None
            # v4: Format file_size for display
            st["file_size_display"] = _format_size(st["file_size"]) if st["file_size"] > 0 else "0 bytes"
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
                run_ssh_command("rm -f /tmp/*.pcap /tmp/*.pcap[0-9]* 2>/dev/null", timeout=10)
                logger.info("Cleanup completed")
                return True, "Cleanup completed"
            return False, f"Cleanup failed: {stderr or stdout}"
        except Exception as e:
            logger.error("Cleanup error: %s", e)
            return False, f"Cleanup error: {e}"

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------

    def start_capture(self, band: str, auto_sync_time: bool = True) -> Tuple[bool, str]:
        if band not in _VALID_BANDS:
            return False, f"Invalid band: {band}"
        interface = self._iface_svc.interfaces.get(band)
        if not interface:
            return False, f"No interface mapped for {band}"
        if not _SAFE_IFACE.match(interface):
            return False, f"Invalid interface name: {interface}"

        with self._status_lock:
            if self._status[band]["running"]:
                return False, f"{band} capture already running"

        try:
            # Auto-sync time before first capture
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
                self._status[band]["file_size"] = 0

            # Start monitor thread
            t = threading.Thread(target=self._monitor_capture, args=(band,), daemon=True)
            t.start()
            self._broadcast()
            return True, f"{band} capture started on {interface}"
        except Exception as e:
            logger.error("Start capture error: %s", e)
            return False, f"Error starting capture: {e}"

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------

    def stop_capture(self, band: str, product_name: str = "", sw_version: str = "") -> Tuple[bool, str, Optional[str]]:
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
            ok, msg, path = self._downloader.download_pcap_files(
                band, timestamp, product_name=product_name, sw_version=sw_version
            )

            with self._status_lock:
                self._status[band]["running"] = False
                self._status[band]["start_time"] = None
                self._status[band]["file_size"] = 0
            self._broadcast()
            return ok, msg, path
        except Exception as e:
            with self._status_lock:
                self._status[band]["running"] = False
                self._status[band]["start_time"] = None
                self._status[band]["file_size"] = 0
            return False, f"Error stopping capture: {e}", None

    def stop_all_captures(self, product_name: str = "", sw_version: str = "") -> Dict[str, Dict[str, Any]]:
        """Stop all bands, kill all tcpdump, download pcap files."""
        results: Dict[str, Dict[str, Any]] = {}

        # Snapshot which bands were running before we kill anything
        with self._status_lock:
            was_running = {b: self._status[b]["running"] for b in ("2G", "5G", "6G")}

        logger.info("stop_all: killing all tcpdump on OpenWrt")
        ok, stdout, stderr = run_ssh_command("killall tcpdump 2>/dev/null; echo KILL_DONE", timeout=15)
        if not ok or "KILL_DONE" not in stdout:
            logger.error("stop_all SSH failed: %s", stderr)
            for b in ("2G", "5G", "6G"):
                results[b] = {"success": False, "message": f"SSH error: {stderr or 'Cannot connect'}", "path": None}
            return results

        time.sleep(2)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for band in ("2G", "5G", "6G"):
            if was_running[band]:
                ok, msg, path = self._downloader.download_pcap_files(
                    band, timestamp, product_name=product_name, sw_version=sw_version
                )
                results[band] = {"success": ok, "message": msg, "path": path}
            else:
                results[band] = {"success": True, "message": f"{band} was not running", "path": None}
            with self._status_lock:
                self._status[band]["running"] = False
                self._status[band]["start_time"] = None
                self._status[band]["file_size"] = 0

        self._broadcast()
        logger.info("stop_all completed: %s", results)
        return results

    # ------------------------------------------------------------------
    # Monitor — v4: tracks real file size
    # ------------------------------------------------------------------

    def _is_running(self, band: str) -> bool:
        """Thread-safe check for capture running state."""
        with self._status_lock:
            return self._status[band]["running"]

    def _monitor_capture(self, band: str):
        """Background thread that polls remote file size and broadcasts updates."""
        while self._is_running(band):
            try:
                remote = f"/tmp/{band}.pcap"
                # Get total size of all pcap files for this band
                ok, stdout, stderr = run_ssh_command(
                    f"ls -la {remote}* 2>/dev/null | awk '{{s+=$5}} END {{print s+0}}'",
                    timeout=8,
                )
                if ok and stdout.strip():
                    try:
                        size = int(float(stdout.strip()))
                        with self._status_lock:
                            self._status[band]["file_size"] = size
                        self._monitor_error_count[band] = 0
                        # Broadcast updated status to WebSocket clients
                        self._broadcast()
                    except (ValueError, OverflowError):
                        pass
                else:
                    self._monitor_error_count[band] += 1
                    if self._monitor_error_count[band] == MONITOR_ERROR_THRESHOLD:
                        logger.warning("%s: monitor SSH errors (%dx)", band, MONITOR_ERROR_THRESHOLD)
            except Exception as e:
                self._monitor_error_count[band] += 1
                if self._monitor_error_count[band] == MONITOR_ERROR_THRESHOLD:
                    logger.warning("%s: monitor exception: %s", band, e)
            time.sleep(MONITOR_INTERVAL)
