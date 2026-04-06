"""
File Download Service
=====================
Downloads pcap files from OpenWrt and handles multi-file (split) scenarios.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from ..config import DOWNLOADS_FOLDER
from ..ssh import run_ssh_command, download_file

logger = logging.getLogger(__name__)


def _format_size(total_bytes: int) -> str:
    if total_bytes >= 1024 * 1024 * 1024:
        return f"{total_bytes / (1024**3):.2f} GB"
    if total_bytes >= 1024 * 1024:
        return f"{total_bytes / (1024**2):.1f} MB"
    if total_bytes >= 1024:
        return f"{total_bytes / 1024:.1f} KB"
    return f"{total_bytes:,} bytes"


class FileDownloader:
    """Downloads pcap files for a given band from the router."""

    @staticmethod
    def _build_filename_prefix(band: str, product_name: str = "", sw_version: str = "") -> str:
        """Build filename prefix like 'RAX50_V1.0.3_5G_sniffer' or '5G_sniffer'."""
        parts = []
        if product_name:
            parts.append(product_name)
        if sw_version:
            parts.append(sw_version)
        parts.append(band)
        parts.append("sniffer")
        return "_".join(parts)

    def download_pcap_files(
        self, band: str, timestamp: str,
        product_name: str = "", sw_version: str = "",
    ) -> Tuple[bool, str, Optional[str]]:
        """
        List, download, and remove remote pcap files for *band*.
        Returns (success, message, local_path_or_folder).
        """
        remote_path = f"/tmp/{band}.pcap"

        ok, stdout, stderr = run_ssh_command(f"ls -1 {remote_path}* 2>/dev/null", timeout=5)
        if not ok:
            logger.warning("%s: SSH error listing files: %s", band, stderr)
            return False, f"SSH error: {stderr or 'Connection failed'}", None
        if not stdout.strip():
            logger.info("%s: No capture files found", band)
            return False, "No capture file found on router", None

        remote_files = [f.strip() for f in stdout.strip().splitlines() if f.strip()]
        logger.info("%s: Found %d file(s): %s", band, len(remote_files), remote_files)

        # Ensure download directory exists
        os.makedirs(DOWNLOADS_FOLDER, exist_ok=True)

        # Build filename prefix (e.g. "RAX50_V1.0.3_5G_sniffer" or "5G_sniffer")
        prefix = self._build_filename_prefix(band, product_name, sw_version)

        downloaded: List[str] = []
        failed: List[str] = []
        total_size = 0

        for idx, remote_file in enumerate(remote_files):
            if len(remote_files) == 1:
                local_name = f"{prefix}_{timestamp}.pcap"
            else:
                local_name = f"{prefix}_{timestamp}_part{idx + 1:03d}.pcap"

            local_path = os.path.join(DOWNLOADS_FOLDER, local_name)
            logger.info("%s: Downloading %s -> %s", band, remote_file, local_path)

            if download_file(remote_file, local_path) and os.path.exists(local_path):
                fsize = os.path.getsize(local_path)
                total_size += fsize
                downloaded.append(local_name)
                logger.info("%s: OK %s", band, _format_size(fsize))
            else:
                failed.append(remote_file)
                logger.warning("%s: Download failed for %s", band, remote_file)

        # Clean up remote files
        run_ssh_command(f"rm -f {remote_path}*", timeout=5)

        if not downloaded:
            msg = "Download failed"
            if failed:
                msg += f": Could not download {len(failed)} file(s)"
            return False, msg, None

        size_str = _format_size(total_size)
        if len(downloaded) == 1:
            msg = f"Saved: {downloaded[0]} ({size_str})"
            path = os.path.join(DOWNLOADS_FOLDER, downloaded[0])
        else:
            msg = f"Saved {len(downloaded)} files ({size_str} total)"
            path = DOWNLOADS_FOLDER

        if failed:
            msg += f" (Warning: {len(failed)} file(s) failed)"

        return True, msg, path
