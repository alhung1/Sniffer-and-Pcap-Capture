"""
Interface Detection Service
============================
Auto-detects OpenWrt interface-to-band mapping via iwconfig / UCI.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from ..config import DEFAULT_INTERFACES, DEFAULT_UCI_WIFI_MAP
from ..ssh import run_ssh_command

logger = logging.getLogger(__name__)


class InterfaceService:
    """Detects and tracks the mapping between ath interfaces and WiFi bands."""

    def __init__(self):
        self.interfaces: Dict[str, str] = dict(DEFAULT_INTERFACES)
        self.uci_wifi_map: Dict[str, str] = dict(DEFAULT_UCI_WIFI_MAP)
        self.detection_status: Dict[str, Any] = {
            "detected": False,
            "last_detection": None,
            "detection_method": None,
            "detected_mapping": None,
        }

    def detect_interfaces(self) -> bool:
        """Auto-detect interface mapping from OpenWrt via iwconfig frequency."""
        logger.info("Starting interface auto-detection...")

        try:
            success, stdout, stderr = run_ssh_command(
                "iwconfig 2>/dev/null | grep -E '^ath[0-2]|Frequency'",
                timeout=10,
            )
            if not success or not stdout.strip():
                logger.warning("Auto-detection failed (no iwconfig output), using defaults")
                return False

            detected: Dict[str, str] = {}
            current_iface: Optional[str] = None

            for line in stdout.strip().splitlines():
                line = line.strip()
                if line.startswith("ath"):
                    current_iface = line.split()[0]
                elif "Frequency" in line and current_iface:
                    match = re.search(r"Frequency[:\s]*(\d+\.?\d*)", line)
                    if match:
                        freq = float(match.group(1))
                        if freq < 3:
                            band = "2G"
                        elif freq < 6:
                            band = "5G"
                        else:
                            band = "6G"
                        detected[current_iface] = band
                        logger.info("%s: %.3f GHz -> %s", current_iface, freq, band)

            if len(detected) < 3:
                logger.warning("Auto-detection incomplete (%d/3), using defaults", len(detected))
                return False

            new_mapping = {band: iface for iface, band in detected.items()}
            if not all(b in new_mapping for b in ("2G", "5G", "6G")):
                logger.warning("Missing bands in detection result")
                return False

            self.interfaces = new_mapping
            self.detection_status.update({
                "detected": True,
                "last_detection": datetime.now(),
                "detection_method": "iwconfig_frequency",
                "detected_mapping": dict(self.interfaces),
            })
            logger.info("Detection OK – mapping: %s", self.interfaces)
            self._detect_uci_wifi_mapping()
            return True

        except Exception as e:
            logger.error("Detection error: %s", e)
            return False

    # ------------------------------------------------------------------

    def _detect_uci_wifi_mapping(self):
        """Determine which UCI radio (wifi0/1/2) maps to which band."""
        try:
            success, stdout, _ = run_ssh_command(
                "uci show wireless | grep -E 'wifi[0-2]\\.(channel|htmode|band|hwmode)'",
                timeout=10,
            )
            if not success or not stdout.strip():
                return

            uci_data: Dict[str, Dict[str, str]] = {}
            for line in stdout.strip().splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.replace("wireless.", "")
                value = value.strip("'\"")
                parts = key.split(".")
                if len(parts) == 2:
                    radio, prop = parts
                    uci_data.setdefault(radio, {})[prop] = value

            logger.debug("UCI raw data: %s", uci_data)

            for radio, cfg in uci_data.items():
                try:
                    channel = int(cfg.get("channel", 0))
                    htmode = cfg.get("htmode", "")
                    if channel <= 0:
                        continue
                    if channel <= 14:
                        band = "2G"
                    elif channel <= 177:
                        band = "5G"
                    else:
                        band = "6G"
                    self.uci_wifi_map[band] = radio
                    logger.info("UCI: %s -> %s (CH%d %s)", radio, band, channel, htmode)
                except (ValueError, KeyError) as e:
                    logger.debug("UCI parse skip for %s: %s", radio, e)

            logger.info("UCI mapping: %s", self.uci_wifi_map)
        except Exception as e:
            logger.error("UCI detection error: %s", e)
