"""
Interface Detection Service
============================
Auto-detects OpenWrt ath-interface to WiFi-band mapping.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from ..config import DEFAULT_INTERFACES, DEFAULT_UCI_WIFI_MAP
from ..ssh import run_ssh_command

logger = logging.getLogger(__name__)


class InterfaceService:
    """Detects and tracks interface <-> band mapping."""

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
        """Auto-detect via iwconfig frequency parsing."""
        logger.info("Starting interface auto-detection...")

        try:
            ok, stdout, stderr = run_ssh_command(
                "iwconfig 2>/dev/null | grep -E '^ath[0-9]|Frequency'",
                timeout=10,
            )
            if not ok or not stdout.strip():
                logger.warning("Auto-detection failed (no iwconfig output)")
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
                logger.warning("Incomplete detection (%d/3)", len(detected))
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
            logger.info("Detection OK: %s", self.interfaces)
            self._detect_uci_wifi_mapping()
            return True

        except Exception as e:
            logger.error("Detection error: %s", e)
            return False

    def _detect_uci_wifi_mapping(self):
        """Map UCI radio names (wifi0/1/2) to bands."""
        try:
            ok, stdout, _ = run_ssh_command(
                "uci show wireless | grep -E 'wifi[0-2]\\.(channel|htmode|band|hwmode)'",
                timeout=10,
            )
            if not ok or not stdout.strip():
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

            for radio, cfg in uci_data.items():
                try:
                    channel = int(cfg.get("channel", 0))
                    if channel <= 0:
                        continue
                    if channel <= 14:
                        band = "2G"
                    elif channel <= 177:
                        band = "5G"
                    else:
                        band = "6G"
                    self.uci_wifi_map[band] = radio
                    htmode = cfg.get("htmode", "")
                    logger.info("UCI: %s -> %s (CH%d %s)", radio, band, channel, htmode)
                except (ValueError, KeyError) as e:
                    logger.debug("UCI parse skip %s: %s", radio, e)

            logger.info("UCI mapping: %s", self.uci_wifi_map)
        except Exception as e:
            logger.error("UCI detection error: %s", e)
