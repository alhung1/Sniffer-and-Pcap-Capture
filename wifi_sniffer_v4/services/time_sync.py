"""
Time Sync Service
=================
Synchronises OpenWrt clock with the local PC.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Tuple

from ..ssh import run_ssh_command

logger = logging.getLogger(__name__)


class TimeSyncService:

    def __init__(self):
        self.status: Dict[str, Any] = {
            "last_sync": None,
            "offset_seconds": None,
            "success": False,
        }

    def sync_time(self) -> Tuple[bool, str]:
        """Push PC time to OpenWrt."""
        try:
            pc_time = datetime.now()
            time_str = pc_time.strftime("%Y-%m-%d %H:%M:%S")

            # Measure offset before sync
            ok, stdout, _ = run_ssh_command("date '+%Y-%m-%d %H:%M:%S'", timeout=10)
            if ok and stdout.strip():
                try:
                    remote = datetime.strptime(stdout.strip(), "%Y-%m-%d %H:%M:%S")
                    self.status["offset_seconds"] = (pc_time - remote).total_seconds()
                    logger.info("Time offset before sync: %.1fs", self.status["offset_seconds"])
                except ValueError as e:
                    logger.debug("Could not parse remote time: %s", e)

            ok, _, stderr = run_ssh_command(f'date -s "{time_str}"', timeout=10)
            if ok:
                self.status["last_sync"] = pc_time
                self.status["success"] = True
                return True, f"Time synced: {time_str}"

            self.status["success"] = False
            return False, f"Failed to set time: {stderr}"
        except Exception as e:
            self.status["success"] = False
            return False, f"Time sync error: {e}"

    def get_time_info(self) -> Dict[str, Any]:
        """Return PC time, OpenWrt time, and offset."""
        pc_time = datetime.now()
        ok, stdout, _ = run_ssh_command("date '+%Y-%m-%d %H:%M:%S'", timeout=10)

        openwrt_time = None
        offset = None
        if ok and stdout.strip():
            try:
                openwrt_time = datetime.strptime(stdout.strip(), "%Y-%m-%d %H:%M:%S")
                offset = (pc_time - openwrt_time).total_seconds()
            except ValueError:
                pass

        return {
            "pc_time": pc_time.strftime("%Y-%m-%d %H:%M:%S"),
            "openwrt_time": stdout.strip() if ok else "Unknown",
            "offset_seconds": offset,
            "synced": abs(offset) < 2 if offset is not None else False,
        }
