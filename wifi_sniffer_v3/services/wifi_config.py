"""
WiFi Config Service
===================
Manages channel / bandwidth configuration on OpenWrt.
"""

import logging
import re
import time
from typing import Any, Dict, Optional, Tuple

from ..remote import build_cleanup_stale_captures_command
from ..ssh import run_ssh_command

logger = logging.getLogger(__name__)


class WifiConfigService:
    """
    Reads, stores, and applies channel/bandwidth settings.

    Requires an ``InterfaceService`` reference so it can look up the
    current interface mapping and UCI radio names.
    """

    def __init__(self, interface_service):
        self._iface_svc = interface_service
        self.channel_config: Dict[str, Dict[str, Any]] = {
            "2G": {"channel": 6, "bandwidth": "HT40"},
            "5G": {"channel": 36, "bandwidth": "EHT160"},
            "6G": {"channel": 37, "bandwidth": "EHT320"},
        }

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_channel_config(self) -> Dict[str, Dict[str, Any]]:
        """Return the locally cached channel config (no SSH)."""
        return dict(self.channel_config)

    def get_current_wifi_config(self, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Return channel config, optionally refreshing from OpenWrt UCI.
        """
        if force_refresh:
            for band, uci_radio in self._iface_svc.uci_wifi_map.items():
                if not uci_radio:
                    continue
                ok, stdout, _ = run_ssh_command(
                    f"uci get wireless.{uci_radio}.channel 2>/dev/null; "
                    f"uci get wireless.{uci_radio}.htmode 2>/dev/null",
                    timeout=10,
                )
                if ok and stdout.strip():
                    lines = stdout.strip().splitlines()
                    try:
                        channel = int(lines[0]) if lines[0].isdigit() else 0
                        htmode = lines[1] if len(lines) > 1 else self.channel_config[band]["bandwidth"]
                        if channel > 0:
                            self.channel_config[band]["channel"] = channel
                            self.channel_config[band]["bandwidth"] = htmode
                            logger.info("WiFi config %s: CH%d %s", band, channel, htmode)
                    except (ValueError, IndexError) as e:
                        logger.debug("Parse error for %s: %s", band, e)
        return dict(self.channel_config)

    def sync_channel_config_from_openwrt(self) -> bool:
        """Pull actual channel+htmode from OpenWrt UCI into local cache."""
        try:
            logger.info("Syncing channel config from OpenWrt...")
            for band, uci_radio in self._iface_svc.uci_wifi_map.items():
                if not uci_radio:
                    continue
                ok, stdout, _ = run_ssh_command(
                    f"uci get wireless.{uci_radio}.channel 2>/dev/null; "
                    f"uci get wireless.{uci_radio}.htmode 2>/dev/null",
                    timeout=10,
                )
                if ok and stdout.strip():
                    lines = stdout.strip().splitlines()
                    try:
                        channel = int(lines[0]) if lines[0].isdigit() else 0
                        htmode = lines[1] if len(lines) > 1 else self.channel_config[band]["bandwidth"]
                        if channel > 0:
                            self.channel_config[band]["channel"] = channel
                            self.channel_config[band]["bandwidth"] = htmode
                            logger.info("Config sync %s (%s): CH%d %s", band, uci_radio, channel, htmode)
                    except (ValueError, IndexError) as e:
                        logger.debug("Config sync parse error for %s: %s", band, e)
            logger.info("Final config: %s", self.channel_config)
            return True
        except Exception as e:
            logger.error("Config sync error: %s", e)
            return False

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def set_channel_config(self, band: str, channel: int,
                           bandwidth: Optional[str] = None) -> Tuple[bool, str]:
        self.channel_config[band]["channel"] = channel
        if bandwidth:
            self.channel_config[band]["bandwidth"] = bandwidth
        return True, f"Config updated for {band}: CH{channel} {bandwidth or ''}"

    def apply_all_and_restart_wifi(self) -> Dict[str, Any]:
        """
        Apply 2G/5G via iwconfig, 6G via cfg80211tool. No ``wifi load``.
        """
        results: Dict[str, Any] = {
            "success": True,
            "messages": [],
            "bands": {},
            "method": "iwconfig (2G/5G) + cfg80211tool (6G), no wifi load",
        }

        results["messages"].append("Cleaning up running processes...")
        logger.info("Cleaning up tcpdump before config apply")
        self._cleanup_tcpdump()
        results["messages"].append("Cleanup completed")

        for band in ("2G", "5G"):
            iface = self._iface_svc.interfaces.get(band)
            if not iface:
                results["bands"][band] = {"success": False, "message": f"No interface for {band}"}
                results["messages"].append(f"{band}: No interface configured")
                results["success"] = False
                continue

            target_ch = self.channel_config[band]["channel"]
            results["messages"].append(f"{band}: Setting channel {target_ch} on {iface}...")
            logger.info("iwconfig %s Channel %d", iface, target_ch)

            ok, stdout, stderr = run_ssh_command(f"iwconfig {iface} Channel {target_ch}", timeout=10)
            if not ok:
                results["bands"][band] = {"success": False, "message": f"Failed: {stderr or stdout}"}
                results["messages"].append(f"{band}: Failed - {stderr or stdout}")
                results["success"] = False
                continue

            time.sleep(2)
            actual = self._read_channel_from_iwconfig(iface)
            if actual == target_ch:
                results["bands"][band] = {"success": True, "message": f"Channel set to {target_ch} (verified)"}
                results["messages"].append(f"{band}: Channel {target_ch} set successfully")
            else:
                results["bands"][band] = {
                    "success": False,
                    "message": f"Verification failed: expected {target_ch}, got {actual}",
                }
                results["messages"].append(f"{band}: Verification failed (expected {target_ch}, got {actual})")
                results["success"] = False

        res_6g = self._apply_6g_cfg80211tool()
        results["bands"]["6G"] = res_6g.get("bands", {}).get("6G", {"success": False, "message": "Unknown"})
        results["messages"].extend(res_6g.get("messages", []))
        if not res_6g.get("success", True):
            results["success"] = False

        ok, stdout, _ = run_ssh_command(
            "iwconfig 2>/dev/null | grep -E '^ath[0-2]|Channel|Frequency'", timeout=10,
        )
        if ok and stdout.strip():
            results["interface_status"] = stdout
            results["messages"].append("Interface status updated")

        if results["success"]:
            results["messages"].append("All channel configuration completed (no wifi load)")
        else:
            results["messages"].append("Some channel configurations failed")

        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _cleanup_tcpdump(self):
        ok, stdout, stderr = run_ssh_command(build_cleanup_stale_captures_command(), timeout=10)
        if not ok:
            logger.warning("App capture cleanup before config apply failed: %s", stderr or stdout)

    def _read_channel_from_iwconfig(self, interface: str) -> Optional[int]:
        try:
            ok, stdout, _ = run_ssh_command(f"iwconfig {interface} 2>/dev/null", timeout=10)
            if not ok or not stdout.strip():
                return None
            for pattern in (r"Channel[:\s]+(\d+)", r"channel[:\s]+(\d+)"):
                m = re.search(pattern, stdout, re.IGNORECASE)
                if m:
                    return int(m.group(1))
            return None
        except Exception as e:
            logger.error("Error reading channel for %s: %s", interface, e)
            return None

    def _apply_6g_cfg80211tool(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {"success": True, "messages": [], "bands": {}}
        iface = self._iface_svc.interfaces.get("6G")
        if not iface:
            results["success"] = False
            results["bands"]["6G"] = {"success": False, "message": "No interface for 6G"}
            results["messages"].append("6G: No interface configured")
            return results

        target_ch = self.channel_config["6G"]["channel"]
        results["messages"].append(f"6G: Setting channel {target_ch} on {iface} (cfg80211tool)...")
        logger.info("cfg80211tool %s channel %d 3", iface, target_ch)

        ok, stdout, stderr = run_ssh_command(f"cfg80211tool {iface} channel {target_ch} 3", timeout=10)
        if not ok:
            results["bands"]["6G"] = {"success": False, "message": f"Failed: {stderr or stdout}"}
            results["messages"].append(f"6G: Failed - {stderr or stdout}")
            results["success"] = False
            return results

        time.sleep(2)
        actual = self._read_channel_from_iwconfig(iface)
        if actual == target_ch:
            results["bands"]["6G"] = {"success": True, "message": f"Channel set to {target_ch} (verified)"}
            results["messages"].append(f"6G: Channel {target_ch} set successfully")
        else:
            results["bands"]["6G"] = {
                "success": False,
                "message": f"Verification failed: expected {target_ch}, got {actual}",
            }
            results["messages"].append(f"6G: Verification failed (expected {target_ch}, got {actual})")
            results["success"] = False

        return results
