"""
File Download Service
=====================
Shared logic for downloading app-managed pcap files from OpenWrt.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from ..config import DOWNLOADS_FOLDER
from ..remote import (
    build_list_capture_files_command,
    build_remove_capture_artifacts_command,
    make_capture_paths,
    validate_band,
)
from ..ssh import download_file, run_ssh_command

logger = logging.getLogger(__name__)


def _format_size(total_bytes: int) -> str:
    if total_bytes > 1024 * 1024 * 1024:
        return f"{total_bytes / (1024**3):.2f} GB"
    if total_bytes > 1024 * 1024:
        return f"{total_bytes / (1024**2):.1f} MB"
    return f"{total_bytes:,} bytes"


class FileDownloader:
    """Downloads pcap files created by this application for a given band."""

    def download_pcap_files(
        self,
        band: str,
        timestamp: str,
        session_id: str,
    ) -> tuple[bool, str, Optional[str]]:
        """
        List, download and remove remote pcap files for one app-managed session.

        Returns ``(success, message, local_path_or_folder)``.
        """
        normalized_band = validate_band(band)
        paths = make_capture_paths(normalized_band, session_id)

        ok, stdout, stderr = run_ssh_command(build_list_capture_files_command(paths), timeout=5)
        if not ok:
            logger.warning("%s: SSH error listing files: %s", normalized_band, stderr)
            return False, f"SSH error: {stderr or 'Connection failed'}", None
        if not stdout.strip():
            logger.info("%s: No capture files found for session %s", normalized_band, session_id)
            return False, "No capture file found on router", None

        remote_files = [line.strip() for line in stdout.strip().splitlines() if line.strip()]
        logger.info("%s: Found %d file(s): %s", normalized_band, len(remote_files), remote_files)

        downloaded: list[str] = []
        failed: list[str] = []
        total_size = 0

        for idx, remote_file in enumerate(remote_files):
            if len(remote_files) == 1:
                local_name = f"{normalized_band}_sniffer_{timestamp}.pcap"
            else:
                local_name = f"{normalized_band}_sniffer_{timestamp}_part{idx + 1:03d}.pcap"

            local_path = os.path.join(DOWNLOADS_FOLDER, local_name)
            logger.info("%s: Downloading %s -> %s", normalized_band, remote_file, local_path)

            if download_file(remote_file, local_path) and os.path.exists(local_path):
                file_size = os.path.getsize(local_path)
                total_size += file_size
                downloaded.append(local_name)
                logger.info("%s: OK %s bytes", normalized_band, f"{file_size:,}")
            else:
                failed.append(remote_file)
                logger.warning("%s: Download failed for %s", normalized_band, remote_file)

        run_ssh_command(build_remove_capture_artifacts_command(paths), timeout=5)

        if not downloaded:
            message = "Download failed"
            if failed:
                message += f": Could not download {len(failed)} file(s)"
            return False, message, None

        size_str = _format_size(total_size)
        if len(downloaded) == 1:
            message = f"Saved: {downloaded[0]} ({size_str})"
            path = os.path.join(DOWNLOADS_FOLDER, downloaded[0])
        else:
            message = f"Saved {len(downloaded)} files ({size_str} total)"
            path = DOWNLOADS_FOLDER

        if failed:
            message += f" (Warning: {len(failed)} file(s) failed)"

        return True, message, path
