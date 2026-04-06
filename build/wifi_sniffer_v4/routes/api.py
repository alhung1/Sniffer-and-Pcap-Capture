"""
API Routes v4
=============
REST API with input validation, proper error responses.
"""

import logging
import subprocess
import sys
from pathlib import Path

from flask import current_app, jsonify, request

from . import api_bp
from ..cache import status_cache
import re

from ..config import (
    OPENWRT_HOST, OPENWRT_USER,
    SSH_KEY_PATH, SSH_PORT, CHANNELS, BANDWIDTHS, VERSION,
    CAPTURE_INFO_PATTERN,
)
from ..utils import get_subprocess_startupinfo

logger = logging.getLogger(__name__)

VALID_BANDS = {"2G", "5G", "6G"}


def _svc():
    """Shorthand for accessing services from app.extensions."""
    return (
        current_app.extensions["capture_service"],
        current_app.extensions["interface_service"],
        current_app.extensions["time_sync_service"],
        current_app.extensions["wifi_config_service"],
    )


_SAFE_CAPTURE_INFO = re.compile(CAPTURE_INFO_PATTERN)


def _extract_capture_info():
    """Extract and validate product_name/sw_version from request JSON."""
    data = request.get_json(silent=True) or {}
    product_name = str(data.get("product_name", "")).strip()
    sw_version = str(data.get("sw_version", "")).strip()
    # Validate — reject invalid, keep empty as empty
    if product_name and not _SAFE_CAPTURE_INFO.match(product_name):
        product_name = ""
    if sw_version and not _SAFE_CAPTURE_INFO.match(sw_version):
        sw_version = ""
    return product_name, sw_version


# ------------------------------------------------------------------
# Info
# ------------------------------------------------------------------

@api_bp.route("/version")
def api_version():
    return jsonify({"version": VERSION})


# ------------------------------------------------------------------
# Capture
# ------------------------------------------------------------------

@api_bp.route("/status")
def get_status():
    cap, *_ = _svc()
    return jsonify(cap.get_all_status())


@api_bp.route("/start/<band>", methods=["POST"])
def api_start(band):
    band = band.upper()
    if band not in VALID_BANDS:
        return jsonify({"success": False, "message": f"Invalid band: {band}"}), 400
    cap, *_ = _svc()
    ok, msg = cap.start_capture(band)
    return jsonify({"success": ok, "message": msg})


@api_bp.route("/stop/<band>", methods=["POST"])
def api_stop(band):
    band = band.upper()
    if band not in VALID_BANDS:
        return jsonify({"success": False, "message": f"Invalid band: {band}"}), 400
    cap, *_ = _svc()
    product_name, sw_version = _extract_capture_info()
    ok, msg, path = cap.stop_capture(band, product_name=product_name, sw_version=sw_version)
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
    product_name, sw_version = _extract_capture_info()
    results = cap.stop_all_captures(product_name=product_name, sw_version=sw_version)
    return jsonify({"results": results})


# ------------------------------------------------------------------
# Channel Configuration
# ------------------------------------------------------------------

@api_bp.route("/config/<band>", methods=["POST"])
def api_config(band):
    band = band.upper()
    if band not in VALID_BANDS:
        return jsonify({"success": False, "message": f"Invalid band: {band}"}), 400

    cap, _, _, wifi = _svc()
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Missing JSON body"}), 400

    try:
        channel = int(data.get("channel", wifi.channel_config[band]["channel"]))
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Invalid channel value (must be integer)"}), 400
    bandwidth = data.get("bandwidth", wifi.channel_config[band]["bandwidth"])
    if not isinstance(bandwidth, str):
        return jsonify({"success": False, "message": "Invalid bandwidth value (must be string)"}), 400

    # v4: Validate channel and bandwidth
    if channel not in CHANNELS.get(band, []):
        return jsonify({"success": False, "message": f"Invalid channel {channel} for {band}"}), 400
    if bandwidth not in BANDWIDTHS.get(band, []):
        return jsonify({"success": False, "message": f"Invalid bandwidth {bandwidth} for {band}"}), 400

    ok, msg = wifi.set_channel_config(band, channel, bandwidth)
    return jsonify({"success": ok, "message": msg})


@api_bp.route("/apply_config", methods=["POST"])
def api_apply_config():
    cap, _, _, wifi = _svc()

    # Block if any capture is running
    status = cap.get_all_status()
    for band in ("2G", "5G", "6G"):
        if status[band]["running"]:
            return jsonify({
                "success": False,
                "message": f"Cannot apply config while {band} capture is running. Stop all captures first."
            }), 409

    results = wifi.apply_all_and_restart_wifi()
    return jsonify(results)


@api_bp.route("/get_wifi_config")
def api_get_wifi_config():
    _, iface, _, wifi = _svc()
    config = wifi.get_current_wifi_config(force_refresh=True)
    return jsonify({"success": True, "config": config, "uci_wifi_map": iface.uci_wifi_map})


# ------------------------------------------------------------------
# Connection
# ------------------------------------------------------------------

@api_bp.route("/test_connection")
def api_test_connection():
    from ..ssh import ssh_client
    from .. import perform_startup_cleanup, is_startup_cleanup_done

    cached = status_cache.get("connection_status")
    if cached is not None:
        return jsonify(cached)

    cap, iface, _, wifi = _svc()

    if not ssh_client.is_available:
        result = {
            "connected": False,
            "host": OPENWRT_HOST,
            "error": "SSH is not available on this system. Please install OpenSSH.",
            "ssh_missing": True,
        }
        status_cache.set("connection_status", result)
        return jsonify(result)

    connected = ssh_client.test_connection()

    if connected and not is_startup_cleanup_done():
        perform_startup_cleanup()
        if not iface.detection_status["detected"]:
            iface.detect_interfaces()
            wifi.sync_channel_config_from_openwrt()

    result = {
        "connected": connected,
        "host": OPENWRT_HOST,
        "port": SSH_PORT,
        "user": OPENWRT_USER,
        "auth_method": "key" if SSH_KEY_PATH else "default",
        "ssh_missing": False,
        "error": cap.last_connection_error if not connected else None,
    }
    status_cache.set("connection_status", result)
    return jsonify(result)


@api_bp.route("/diagnose")
def api_diagnose():
    from ..ssh import ssh_client

    ssh_dir = Path.home() / ".ssh"
    ssh_keys_found = [
        name for name in ("id_rsa", "id_ed25519", "id_ecdsa")
        if (ssh_dir / name).exists()
    ]

    cap, *_ = _svc()
    results = {
        "host": OPENWRT_HOST,
        "port": SSH_PORT,
        "user": OPENWRT_USER,
        "ssh_available": ssh_client.is_available,
        "ssh_keys_found": ssh_keys_found,
        "has_ssh_key": len(ssh_keys_found) > 0,
        "ping_test": False,
        "ssh_test": False,
        "error": None,
        "solution": None,
    }

    si = get_subprocess_startupinfo()
    try:
        ping_cmd = ["ping", "-c", "1", "-W", "2", OPENWRT_HOST]
        if sys.platform == "win32":
            ping_cmd = ["ping", "-n", "1", "-w", "2000", OPENWRT_HOST]
        ping_result = subprocess.run(ping_cmd, capture_output=True, timeout=5, startupinfo=si)
        results["ping_test"] = ping_result.returncode == 0
    except Exception as e:
        results["ping_error"] = str(e)

    results["ssh_test"] = ssh_client.test_connection()
    results["error"] = cap.last_connection_error

    if not ssh_client.is_available:
        results["solution"] = "ssh_missing"
        results["solution_text"] = "SSH not found. Install OpenSSH: Settings → Apps → Optional Features → Add OpenSSH Client"
    elif not results["ping_test"]:
        results["solution"] = "network"
        results["solution_text"] = "Cannot reach OpenWrt router. Check: 1) Router powered on, 2) PC connected to router network, 3) Router IP is 192.168.1.1"
    elif not results["ssh_test"]:
        results["solution"] = "ssh_failed"
        results["solution_text"] = "SSH connection failed. Check: 1) SSH/Dropbear enabled on OpenWrt, 2) Try: ssh root@192.168.1.1 in terminal"

    return jsonify(results)


# ------------------------------------------------------------------
# Time
# ------------------------------------------------------------------

@api_bp.route("/time_info")
def api_time_info():
    _, _, tsvc, _ = _svc()
    info = tsvc.get_time_info()
    sync_status = tsvc.status
    info["last_sync"] = sync_status["last_sync"].strftime("%Y-%m-%d %H:%M:%S") if sync_status.get("last_sync") else None
    return jsonify(info)


@api_bp.route("/sync_time", methods=["POST"])
def api_sync_time():
    _, _, tsvc, _ = _svc()
    ok, msg = tsvc.sync_time()
    info = tsvc.get_time_info()
    return jsonify({"success": ok, "message": msg, "time_info": info})


# ------------------------------------------------------------------
# File Split
# ------------------------------------------------------------------

@api_bp.route("/file_split", methods=["GET"])
def api_get_file_split():
    cap, *_ = _svc()
    return jsonify(cap.file_split_config)


@api_bp.route("/file_split", methods=["POST"])
def api_set_file_split():
    cap, *_ = _svc()
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Missing JSON body"}), 400

    cap.update_file_split(
        enabled=data.get("enabled"),
        size_mb=int(data["size_mb"]) if "size_mb" in data else None,
    )
    cfg = cap.file_split_config
    return jsonify({
        "success": True,
        "enabled": cfg["enabled"],
        "size_mb": cfg["size_mb"],
        "message": f"File split {'enabled' if cfg['enabled'] else 'disabled'}"
                   + (f" ({cfg['size_mb']}MB per file)" if cfg["enabled"] else ""),
    })


# ------------------------------------------------------------------
# Capture Info (Product Name / SW Version)
# ------------------------------------------------------------------

@api_bp.route("/capture_info", methods=["GET"])
def api_get_capture_info():
    from ..config import load_persistent_config
    data = load_persistent_config()
    return jsonify({
        "product_name": data.get("product_name", ""),
        "sw_version": data.get("sw_version", ""),
    })


@api_bp.route("/capture_info", methods=["POST"])
def api_set_capture_info():
    from ..config import load_persistent_config, save_persistent_config
    req = request.get_json()
    if not req:
        return jsonify({"success": False, "message": "Missing JSON body"}), 400

    product_name = str(req.get("product_name", "")).strip()
    sw_version = str(req.get("sw_version", "")).strip()

    # Validate
    if product_name and not _SAFE_CAPTURE_INFO.match(product_name):
        return jsonify({"success": False, "message": "Invalid product name. Use only letters, numbers, dot, underscore, hyphen (max 30 chars)."}), 400
    if sw_version and not _SAFE_CAPTURE_INFO.match(sw_version):
        return jsonify({"success": False, "message": "Invalid software version. Use only letters, numbers, dot, underscore, hyphen (max 30 chars)."}), 400

    data = load_persistent_config()
    data["product_name"] = product_name
    data["sw_version"] = sw_version
    save_persistent_config(data)

    parts = []
    if product_name:
        parts.append(product_name)
    if sw_version:
        parts.append(sw_version)
    preview = "_".join(parts + ["{Band}", "sniffer", "{timestamp}.pcap"]) if parts else "{Band}_sniffer_{timestamp}.pcap"

    return jsonify({
        "success": True,
        "product_name": product_name,
        "sw_version": sw_version,
        "message": f"Capture info saved. Filename: {preview}",
    })


# ------------------------------------------------------------------
# Interface Mapping
# ------------------------------------------------------------------

@api_bp.route("/interface_mapping")
def api_get_interface_mapping():
    _, iface, _, wifi = _svc()
    det = iface.detection_status
    return jsonify({
        "interfaces": iface.interfaces,
        "uci_wifi_map": iface.uci_wifi_map,
        "channel_config": wifi.channel_config,
        "detection_status": {
            "detected": det["detected"],
            "last_detection": det["last_detection"].strftime("%Y-%m-%d %H:%M:%S") if det.get("last_detection") else None,
            "detection_method": det.get("detection_method"),
        },
    })


@api_bp.route("/detect_interfaces", methods=["POST"])
def api_detect_interfaces():
    _, iface, _, _ = _svc()
    iface.detection_status["detected"] = False
    ok = iface.detect_interfaces()

    det = iface.detection_status
    return jsonify({
        "success": ok,
        "interfaces": iface.interfaces,
        "uci_wifi_map": iface.uci_wifi_map,
        "detection_status": {
            "detected": det["detected"],
            "last_detection": det["last_detection"].strftime("%Y-%m-%d %H:%M:%S") if det.get("last_detection") else None,
            "detection_method": det.get("detection_method"),
        },
        "message": f"Detection {'OK' if ok else 'failed'}. "
                   f"2G={iface.interfaces.get('2G')}, 5G={iface.interfaces.get('5G')}, 6G={iface.interfaces.get('6G')}",
    })
