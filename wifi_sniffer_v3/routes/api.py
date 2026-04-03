"""
API Routes
==========
REST endpoints for the WiFi Sniffer v3 application.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any, Optional

from flask import current_app, jsonify, request

from . import api_bp
from .. import is_startup_cleanup_done, perform_startup_cleanup
from ..cache import (
    ConnectionStatusPayload,
    get_cached_connection_status,
    set_cached_connection_status,
)
from ..config import (
    BANDWIDTHS,
    CHANNELS,
    OPENWRT_HOST,
    OPENWRT_PASSWORD,
    OPENWRT_USER,
    SSH_KEY_PATH,
    SSH_PORT,
)
from ..remote import RemoteCommandError, validate_band
from ..utils import get_subprocess_startupinfo

logger = logging.getLogger(__name__)

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _svc():
    """Shortcut to grab all four services from the app context."""
    ext = current_app.extensions
    return (
        ext["capture_service"],
        ext["interface_service"],
        ext["time_sync_service"],
        ext["wifi_config_service"],
    )


def _json_error(message: str, status_code: int = 400, **extra):
    payload = {"success": False, "message": message}
    payload.update(extra)
    return jsonify(payload), status_code


def _get_json_body() -> tuple[Optional[dict[str, Any]], Optional[tuple[Any, int]]]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, _json_error("Invalid JSON body")
    return data, None


def _normalize_band_or_error(band: str, interfaces: dict[str, str]):
    try:
        normalized_band = validate_band(band)
    except RemoteCommandError as exc:
        return None, _json_error(str(exc))

    if normalized_band not in interfaces:
        return None, _json_error(f"Invalid band: {normalized_band}")
    return normalized_band, None


def _parse_int_field(
    data: dict[str, Any],
    field_name: str,
    *,
    default: Optional[int] = None,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
):
    if field_name not in data:
        return default, None

    raw_value = data[field_name]
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return None, _json_error(f"{field_name} must be an integer")

    if minimum is not None and value < minimum:
        return None, _json_error(f"{field_name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        return None, _json_error(f"{field_name} must be at most {maximum}")
    return value, None


def _parse_bool_field(data: dict[str, Any], field_name: str):
    if field_name not in data:
        return None, None

    raw_value = data[field_name]
    if isinstance(raw_value, bool):
        return raw_value, None
    if isinstance(raw_value, str):
        normalized = raw_value.strip().lower()
        if normalized in _TRUE_VALUES:
            return True, None
        if normalized in _FALSE_VALUES:
            return False, None
    return None, _json_error(f"{field_name} must be a boolean")


# ------------------------------------------------------------------
# Status
# ------------------------------------------------------------------


@api_bp.route("/status")
def get_status():
    cap, *_ = _svc()
    return jsonify(cap.get_all_status())


# ------------------------------------------------------------------
# Capture controls
# ------------------------------------------------------------------


@api_bp.route("/start/<band>", methods=["POST"])
def api_start(band):
    cap, iface_svc, *_ = _svc()
    band, error = _normalize_band_or_error(band, iface_svc.interfaces)
    if error:
        return error
    ok, msg = cap.start_capture(band)
    return jsonify({"success": ok, "message": msg})


@api_bp.route("/stop/<band>", methods=["POST"])
def api_stop(band):
    cap, iface_svc, *_ = _svc()
    band, error = _normalize_band_or_error(band, iface_svc.interfaces)
    if error:
        return error
    ok, msg, path = cap.stop_capture(band)
    return jsonify({"success": ok, "message": msg, "path": path})


@api_bp.route("/start_all", methods=["POST"])
def api_start_all():
    cap, *_ = _svc()
    results = {}
    for band in ("2G", "5G", "6G"):
        ok, msg = cap.start_capture(band)
        results[band] = {"success": ok, "message": msg}
    return jsonify({"results": results})


@api_bp.route("/stop_all", methods=["POST"])
def api_stop_all():
    cap, *_ = _svc()
    return jsonify({"results": cap.stop_all_captures()})


# ------------------------------------------------------------------
# Channel configuration
# ------------------------------------------------------------------


@api_bp.route("/config/<band>", methods=["POST"])
def api_config(band):
    _, iface_svc, __, wifi_svc = _svc()
    band, error = _normalize_band_or_error(band, iface_svc.interfaces)
    if error:
        return error

    data, error = _get_json_body()
    if error:
        return error

    default_channel = wifi_svc.channel_config[band]["channel"]
    channel, error = _parse_int_field(data, "channel", default=default_channel)
    if error:
        return error
    if channel not in CHANNELS[band]:
        return _json_error(f"Invalid channel for {band}: {channel}")

    bandwidth = data.get("bandwidth", wifi_svc.channel_config[band]["bandwidth"])
    if bandwidth not in BANDWIDTHS[band]:
        return _json_error(f"Invalid bandwidth for {band}: {bandwidth}")

    ok, msg = wifi_svc.set_channel_config(band, channel, bandwidth)
    return jsonify({"success": ok, "message": msg})


@api_bp.route("/apply_config", methods=["POST"])
def api_apply_config():
    cap, _, __, wifi_svc = _svc()
    status = cap.get_all_status()
    for band in ("2G", "5G", "6G"):
        if status[band]["running"] or status[band]["pending_action"]:
            return jsonify(
                {
                    "success": False,
                    "message": f"Cannot apply config while {band} capture is active. Stop all captures first.",
                }
            )

    results = wifi_svc.apply_all_and_restart_wifi()
    if "method" not in results:
        results["method"] = "iwconfig (2G/5G) + cfg80211tool (6G)"
    return jsonify(results)


@api_bp.route("/get_wifi_config")
def api_get_wifi_config():
    _, iface_svc, __, wifi_svc = _svc()
    cfg = wifi_svc.get_current_wifi_config(force_refresh=True)
    return jsonify({"success": True, "config": cfg, "uci_wifi_map": iface_svc.uci_wifi_map})


# ------------------------------------------------------------------
# Connection
# ------------------------------------------------------------------


@api_bp.route("/test_connection")
def api_test_connection():
    cap, iface_svc, _, wifi_svc = _svc()
    from ..ssh import ssh_client

    cached = get_cached_connection_status()
    if cached is not None:
        return jsonify(cached)

    connected = ssh_client.test_connection()
    if connected and not is_startup_cleanup_done():
        perform_startup_cleanup()
        if not iface_svc.detection_status["detected"]:
            iface_svc.detect_interfaces()
            wifi_svc.sync_channel_config_from_openwrt()

    result: ConnectionStatusPayload = {
        "connected": connected,
        "host": OPENWRT_HOST,
        "port": SSH_PORT,
        "user": OPENWRT_USER,
        "auth_method": "publickey" if SSH_KEY_PATH else "default_key_lookup",
        "error": cap.last_connection_error if not connected else None,
    }
    set_cached_connection_status(result)
    return jsonify(result)


@api_bp.route("/diagnose")
def api_diagnose():
    cap, *_ = _svc()
    from ..ssh import ssh_client

    ssh_dir = Path.home() / ".ssh"
    ssh_keys = [key for key in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa") if (ssh_dir / key).exists()]

    results = {
        "host": OPENWRT_HOST,
        "port": SSH_PORT,
        "user": OPENWRT_USER,
        "password_set": bool(OPENWRT_PASSWORD),
        "password_supported": False,
        "auth_mode": "publickey",
        "key_path": SSH_KEY_PATH,
        "ssh_keys_found": ssh_keys,
        "has_ssh_key": len(ssh_keys) > 0,
        "ping_test": False,
        "ssh_test": False,
        "error": None,
        "solution": None,
    }

    startupinfo = get_subprocess_startupinfo()
    try:
        ping = subprocess.run(
            ["ping", "-n", "1", "-w", "2000", OPENWRT_HOST],
            capture_output=True,
            timeout=5,
            startupinfo=startupinfo,
        )
        results["ping_test"] = ping.returncode == 0
    except Exception as exc:
        results["ping_error"] = str(exc)

    results["ssh_test"] = ssh_client.test_connection()
    results["error"] = cap.last_connection_error

    if not results["ping_test"]:
        results["solution"] = "network"
        results["solution_text"] = (
            "Cannot reach OpenWrt router. Check: "
            "1) Router is powered on, "
            "2) PC is connected to router network, "
            f"3) Router IP is {OPENWRT_HOST}"
        )
    elif not results["ssh_test"]:
        results["solution"] = "ssh_failed"
        results["solution_text"] = (
            "SSH connection failed. Check: "
            "1) SSH/Dropbear is enabled on OpenWrt, "
            f"2) Try: ssh {OPENWRT_USER}@{OPENWRT_HOST} in terminal"
        )

    return jsonify(results)


# ------------------------------------------------------------------
# Time
# ------------------------------------------------------------------


@api_bp.route("/time_info")
def api_time_info():
    _, __, time_svc, ___ = _svc()
    info = time_svc.get_time_info()
    info["last_sync"] = (
        time_svc.status["last_sync"].strftime("%Y-%m-%d %H:%M:%S")
        if time_svc.status.get("last_sync")
        else None
    )
    return jsonify(info)


@api_bp.route("/sync_time", methods=["POST"])
def api_sync_time():
    _, __, time_svc, ___ = _svc()
    ok, msg = time_svc.sync_time()
    return jsonify({"success": ok, "message": msg, "time_info": time_svc.get_time_info()})


# ------------------------------------------------------------------
# File split
# ------------------------------------------------------------------


@api_bp.route("/file_split", methods=["GET"])
def api_get_file_split():
    cap, *_ = _svc()
    return jsonify(
        {
            "enabled": cap.file_split_config["enabled"],
            "size_mb": cap.file_split_config["size_mb"],
        }
    )


@api_bp.route("/file_split", methods=["POST"])
def api_set_file_split():
    cap, *_ = _svc()
    data, error = _get_json_body()
    if error:
        return error

    enabled, error = _parse_bool_field(data, "enabled")
    if error:
        return error

    size_mb, error = _parse_int_field(data, "size_mb", minimum=10, maximum=2000)
    if error:
        return error

    if enabled is not None:
        cap.file_split_config["enabled"] = enabled
    if size_mb is not None:
        cap.file_split_config["size_mb"] = size_mb

    enabled = cap.file_split_config["enabled"]
    size_mb = cap.file_split_config["size_mb"]
    message = f"File split {'enabled' if enabled else 'disabled'}"
    if enabled:
        message += f" ({size_mb}MB per file)"

    return jsonify({"success": True, "enabled": enabled, "size_mb": size_mb, "message": message})


# ------------------------------------------------------------------
# Interfaces
# ------------------------------------------------------------------


@api_bp.route("/interface_mapping")
def api_get_interface_mapping():
    _, iface_svc, __, wifi_svc = _svc()
    det = iface_svc.detection_status
    return jsonify(
        {
            "interfaces": iface_svc.interfaces,
            "uci_wifi_map": iface_svc.uci_wifi_map,
            "channel_config": wifi_svc.get_channel_config(),
            "detection_status": {
                "detected": det["detected"],
                "last_detection": det["last_detection"].strftime("%Y-%m-%d %H:%M:%S")
                if det.get("last_detection")
                else None,
                "detection_method": det.get("detection_method"),
                "detected_mapping": det.get("detected_mapping"),
            },
        }
    )


@api_bp.route("/detect_interfaces", methods=["POST"])
def api_detect_interfaces():
    _, iface_svc, __, wifi_svc = _svc()
    iface_svc.detection_status["detected"] = False
    ok = iface_svc.detect_interfaces()
    if ok:
        wifi_svc.sync_channel_config_from_openwrt()

    det = iface_svc.detection_status
    return jsonify(
        {
            "success": ok,
            "interfaces": iface_svc.interfaces,
            "uci_wifi_map": iface_svc.uci_wifi_map,
            "channel_config": wifi_svc.get_channel_config(),
            "detection_status": {
                "detected": det["detected"],
                "last_detection": det["last_detection"].strftime("%Y-%m-%d %H:%M:%S")
                if det.get("last_detection")
                else None,
                "detection_method": det.get("detection_method"),
            },
            "message": (
                f"Detection {'successful' if ok else 'failed'}. "
                f"Mapping: 2G={iface_svc.interfaces.get('2G')}, "
                f"5G={iface_svc.interfaces.get('5G')}, "
                f"6G={iface_svc.interfaces.get('6G')}"
            ),
        }
    )
