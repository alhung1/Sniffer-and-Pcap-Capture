"""
WiFi Config Service
===================
Channel / bandwidth read, store, and apply.
"""

import logging
import re
import time
from typing import Any, Dict, Optional, Tuple

from ..ssh import run_ssh_command
from ..config import load_persistent_config, save_persistent_config

logger = logging.getLogger(__name__)

# Regex for valid interface/radio names — prevents shell injection
_SAFE_IFACE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,15}$")


def _sanitize_iface(name: str) -> str:
    """Validate interface name to prevent shell injection."""
    if not name or not _SAFE_IFACE.match(name):
        raise ValueError(f"Invalid interface name: {name!r}")
    return name


def _freq_ghz_to_channel(freq_ghz: float) -> int:
    """Convert frequency in GHz (e.g. 5.22) to WiFi channel number."""
    freq_mhz = int(round(freq_ghz * 1000))

    # 2.4 GHz band
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if freq_mhz == 2484:
        return 14

    # 5 GHz band (5180-5825 MHz)
    if 5180 <= freq_mhz <= 5825:
        return (freq_mhz - 5000) // 5

    # 6 GHz band (5955-7115 MHz)
    if 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5

    return 0  # unknown


class WifiConfigService:

    def __init__(self, interface_service):
        self._iface_svc = interface_service
        self.channel_config: Dict[str, Dict[str, Any]] = {
            "2G": {"channel": 6, "bandwidth": "HT40"},
            "5G": {"channel": 36, "bandwidth": "EHT160"},
            "6G": {"channel": 37, "bandwidth": "EHT320"},
        }
        # v4: Restore from persistent config if available
        self._load_saved_config()

    def _load_saved_config(self):
        data = load_persistent_config()
        saved = data.get("channel_config")
        if saved and isinstance(saved, dict):
            for band in ("2G", "5G", "6G"):
                if band in saved and isinstance(saved[band], dict):
                    if "channel" in saved[band]:
                        self.channel_config[band]["channel"] = int(saved[band]["channel"])
                    if "bandwidth" in saved[band]:
                        self.channel_config[band]["bandwidth"] = saved[band]["bandwidth"]
            logger.info("Restored channel config from disk: %s", self.channel_config)

    def _save_config(self):
        data = load_persistent_config()
        data["channel_config"] = self.channel_config
        save_persistent_config(data)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_channel_config(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.channel_config)

    def get_current_wifi_config(self, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
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
                        channel = int(lines[0]) if lines[0].strip().isdigit() else 0
                        htmode = lines[1].strip() if len(lines) > 1 else self.channel_config[band]["bandwidth"]
                        if channel > 0:
                            self.channel_config[band]["channel"] = channel
                            self.channel_config[band]["bandwidth"] = htmode
                            logger.info("UCI refresh %s: CH%d %s", band, channel, htmode)
                    except (ValueError, IndexError) as e:
                        logger.debug("Parse error %s: %s", band, e)
        return dict(self.channel_config)

    def sync_channel_config_from_openwrt(self) -> bool:
        """Pull actual config from UCI into local cache and persist."""
        try:
            logger.info("Syncing channel config from OpenWrt...")
            self.get_current_wifi_config(force_refresh=True)
            self._save_config()
            logger.info("Config synced and saved: %s", self.channel_config)
            return True
        except Exception as e:
            logger.error("Config sync error: %s", e)
            return False

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def set_channel_config(self, band: str, channel: int,
                           bandwidth: Optional[str] = None) -> Tuple[bool, str]:
        self.channel_config[band]["channel"] = channel
        if bandwidth:
            self.channel_config[band]["bandwidth"] = bandwidth
        self._save_config()
        return True, f"Config updated for {band}: CH{channel} {bandwidth or ''}"

    def apply_all_and_restart_wifi(self) -> Dict[str, Any]:
        """Apply 2G/5G via iwconfig, 6G via cfg80211tool. No wifi load."""
        results: Dict[str, Any] = {
            "success": True,
            "messages": [],
            "bands": {},
            "method": "iwconfig (2G/5G) + cfg80211tool (6G)",
        }

        results["messages"].append("Cleaning up running processes...")
        self._cleanup_tcpdump()
        results["messages"].append("Cleanup completed")

        # 2G and 5G via iwconfig
        for band in ("2G", "5G"):
            iface = self._iface_svc.interfaces.get(band)
            if not iface:
                results["bands"][band] = {"success": False, "message": f"No interface for {band}"}
                results["success"] = False
                continue

            target_ch = self.channel_config[band]["channel"]
            iface = _sanitize_iface(iface)
            results["messages"].append(f"{band}: Setting channel {target_ch} on {iface}...")

            ok, stdout, stderr = run_ssh_command(f"iwconfig {iface} Channel {target_ch}", timeout=10)
            if not ok:
                results["bands"][band] = {"success": False, "message": f"Failed: {stderr or stdout}"}
                results["success"] = False
                continue

            time.sleep(2)
            actual = self._read_channel_from_iwconfig(iface)
            if actual == target_ch:
                results["bands"][band] = {"success": True, "message": f"Channel set to {target_ch} (verified)"}
                results["messages"].append(f"{band}: Channel {target_ch} OK")
            else:
                results["bands"][band] = {"success": False, "message": f"Expected CH{target_ch}, got CH{actual}"}
                results["messages"].append(f"{band}: Verification failed (expected {target_ch}, got {actual})")
                results["success"] = False

        # 6G via cfg80211tool
        res_6g = self._apply_6g_cfg80211tool()
        results["bands"]["6G"] = res_6g.get("bands", {}).get("6G", {"success": False, "message": "Unknown"})
        results["messages"].extend(res_6g.get("messages", []))
        if not res_6g.get("success", True):
            results["success"] = False

        # Read final status
        ok, stdout, _ = run_ssh_command(
            "iwconfig 2>/dev/null | grep -E '^ath[0-9]|Channel|Frequency'", timeout=10,
        )
        if ok and stdout.strip():
            results["interface_status"] = stdout
            results["messages"].append("Interface status updated")

        if results["success"]:
            results["messages"].append("All channel configurations applied successfully")
        else:
            results["messages"].append("Some configurations failed — see details above")

        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _cleanup_tcpdump(self):
        run_ssh_command("killall tcpdump 2>/dev/null; echo DONE", timeout=10)

    def _read_channel_from_iwconfig(self, interface: str) -> Optional[int]:
        """Read current channel from iwconfig, parsing Channel or Frequency."""
        try:
            interface = _sanitize_iface(interface)
            ok, stdout, _ = run_ssh_command(f"iwconfig {interface} 2>/dev/null", timeout=10)
            if not ok or not stdout.strip():
                return None

            # Try direct Channel field first
            for pattern in (r"Channel[:\s]+(\d+)", r"channel[:\s]+(\d+)"):
                m = re.search(pattern, stdout, re.IGNORECASE)
                if m:
                    return int(m.group(1))

            # Fallback: parse Frequency and convert to channel
            freq_match = re.search(r"Frequency[:\s]+([\d.]+)\s*GHz", stdout, re.IGNORECASE)
            if freq_match:
                freq_ghz = float(freq_match.group(1))
                ch = _freq_ghz_to_channel(freq_ghz)
                if ch > 0:
                    logger.debug("Parsed channel %d from frequency %.3f GHz", ch, freq_ghz)
                    return ch

            return None
        except Exception as e:
            logger.error("Read channel %s: %s", interface, e)
            return None

    def _apply_6g_cfg80211tool(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {"success": True, "messages": [], "bands": {}}
        iface = self._iface_svc.interfaces.get("6G")
        if not iface:
            results["success"] = False
            results["bands"]["6G"] = {"success": False, "message": "No interface for 6G"}
            return results

        target_ch = self.channel_config["6G"]["channel"]
        iface = _sanitize_iface(iface)
        results["messages"].append(f"6G: Setting CH{target_ch} on {iface} (cfg80211tool)...")

        ok, stdout, stderr = run_ssh_command(f"cfg80211tool {iface} channel {target_ch} 3", timeout=10)
        cmd_output = (stderr or stdout).strip()
        if not ok:
            logger.warning("cfg80211tool returned error for CH%d: %s", target_ch, cmd_output)
            # Don't return early — still check actual channel (some errors are non-fatal)

        time.sleep(2)
        actual = self._read_channel_from_iwconfig(iface)
        if actual == target_ch:
            results["bands"]["6G"] = {"success": True, "message": f"Channel set to {target_ch} (verified)"}
            results["messages"].append(f"6G: Channel {target_ch} OK")
        else:
            error_detail = f"Expected CH{target_ch}, got CH{actual}"
            if cmd_output:
                error_detail += f" (driver: {cmd_output})"
            results["bands"]["6G"] = {"success": False, "message": error_detail}
            results["messages"].append(f"6G: Channel {target_ch} failed — {error_detail}")
            results["success"] = False
        return results
