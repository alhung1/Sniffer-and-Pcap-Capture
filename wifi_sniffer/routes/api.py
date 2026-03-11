"""
API Routes
==========
REST API endpoints for the WiFi Sniffer application.
"""

import subprocess
import sys
from pathlib import Path
from flask import jsonify, request

from . import api_bp
from ..capture import capture_manager
from ..ssh import ssh_pool, run_ssh_command
from ..cache import (
    status_cache, 
    get_cached_connection_status, 
    set_cached_connection_status,
    get_cached_interface_mapping,
    set_cached_interface_mapping
)
from ..config import (
    OPENWRT_HOST, OPENWRT_USER, OPENWRT_PASSWORD,
    SSH_KEY_PATH, SSH_PORT, CHANNELS, BANDWIDTHS
)
from .. import perform_startup_cleanup, is_startup_cleanup_done


def _get_subprocess_startupinfo():
    """Get subprocess startupinfo to hide console window on Windows"""
    if sys.platform == "win32":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
        return startupinfo
    return None


@api_bp.route('/status')
def get_status():
    """Get capture status for all bands"""
    return jsonify(capture_manager.get_all_status())


@api_bp.route('/start/<band>', methods=['POST'])
def api_start(band):
    """Start capture for a specific band"""
    band = band.upper()
    if band not in capture_manager.interfaces:
        return jsonify({"success": False, "message": f"Invalid band: {band}"})
    
    success, message = capture_manager.start_capture(band)
    return jsonify({"success": success, "message": message})


@api_bp.route('/stop/<band>', methods=['POST'])
def api_stop(band):
    """Stop capture for a specific band"""
    band = band.upper()
    if band not in capture_manager.interfaces:
        return jsonify({"success": False, "message": f"Invalid band: {band}"})
    
    success, message, path = capture_manager.stop_capture(band)
    return jsonify({"success": success, "message": message, "path": path})


@api_bp.route('/start_all', methods=['POST'])
def api_start_all():
    """Start capture for all bands"""
    results = {}
    for band in ["2G", "5G", "6G"]:
        success, message = capture_manager.start_capture(band)
        results[band] = {"success": success, "message": message}
    return jsonify({"results": results})


@api_bp.route('/stop_all', methods=['POST'])
def api_stop_all():
    """Stop all running captures"""
    results = capture_manager.stop_all_captures()
    return jsonify({"results": results})


@api_bp.route('/config/<band>', methods=['POST'])
def api_config(band):
    """Update channel config for a single band"""
    band = band.upper()
    if band not in capture_manager.interfaces:
        return jsonify({"success": False, "message": f"Invalid band: {band}"})
    
    data = request.get_json()
    channel = int(data.get('channel', capture_manager.channel_config[band]['channel']))
    bandwidth = data.get('bandwidth', capture_manager.channel_config[band]['bandwidth'])
    
    success, message = capture_manager.set_channel_config(band, channel, bandwidth)
    return jsonify({"success": success, "message": message})


@api_bp.route('/apply_config', methods=['POST'])
def api_apply_config():
    """Apply all channel configurations to OpenWrt"""
    # Check if any capture is running
    status = capture_manager.get_all_status()
    for band in ["2G", "5G", "6G"]:
        if status[band]["running"]:
            return jsonify({
                "success": False,
                "message": f"Cannot apply config while {band} capture is running. Stop all captures first."
            })
    
    results = capture_manager.apply_all_and_restart_wifi()
    
    # Ensure method is set in results
    if 'method' not in results:
        if results.get('iwconfig_mode'):
            results['method'] = 'iwconfig (2G/5G only)'
        else:
            results['method'] = 'iwconfig (2G/5G) + cfg80211tool (6G)'
    
    return jsonify(results)


@api_bp.route('/get_wifi_config')
def api_get_wifi_config():
    """Get current WiFi configuration from OpenWrt (force refresh)"""
    config = capture_manager.get_current_wifi_config(force_refresh=True)
    return jsonify({
        "success": True, 
        "config": config,
        "uci_wifi_map": capture_manager.uci_wifi_map
    })


@api_bp.route('/test_connection')
def api_test_connection():
    """Test SSH connection to OpenWrt"""
    # Check cache first
    cached = get_cached_connection_status()
    if cached is not None:
        return jsonify(cached)
    
    connected = ssh_pool.test_connection()
    
    # Perform startup cleanup on first successful connection
    if connected and not is_startup_cleanup_done():
        perform_startup_cleanup()
        # Auto-detect interfaces if not already detected
        if not capture_manager.detection_status["detected"]:
            capture_manager.detect_interfaces()
    
    result = {
        "connected": connected, 
        "host": OPENWRT_HOST,
        "port": SSH_PORT,
        "user": OPENWRT_USER,
        "auth_method": "key" if SSH_KEY_PATH else ("password" if OPENWRT_PASSWORD else "default"),
        "error": capture_manager.last_connection_error if not connected else None
    }
    
    set_cached_connection_status(result)
    return jsonify(result)


@api_bp.route('/diagnose')
def api_diagnose():
    """Diagnostic endpoint for troubleshooting connection issues"""
    # Check for SSH keys
    ssh_dir = Path.home() / ".ssh"
    ssh_keys_found = []
    for key_name in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]:
        key_path = ssh_dir / key_name
        if key_path.exists():
            ssh_keys_found.append(key_name)
    
    results = {
        "host": OPENWRT_HOST,
        "port": SSH_PORT,
        "user": OPENWRT_USER,
        "password_set": OPENWRT_PASSWORD is not None and OPENWRT_PASSWORD != "",
        "no_password_mode": OPENWRT_PASSWORD is None or OPENWRT_PASSWORD == "",
        "key_path": SSH_KEY_PATH,
        "ssh_keys_found": ssh_keys_found,
        "has_ssh_key": len(ssh_keys_found) > 0,
        "ping_test": False,
        "ssh_test": False,
        "error": None,
        "solution": None
    }
    
    # Get startupinfo to hide console window
    startupinfo = _get_subprocess_startupinfo()
    
    # Test ping
    try:
        ping_result = subprocess.run(
            ["ping", "-n", "1", "-w", "2000", OPENWRT_HOST],
            capture_output=True,
            timeout=5,
            startupinfo=startupinfo
        )
        results["ping_test"] = ping_result.returncode == 0
    except Exception as e:
        results["ping_error"] = str(e)
    
    # Test SSH connection
    results["ssh_test"] = ssh_pool.test_connection()
    results["error"] = capture_manager.last_connection_error
    
    # Provide specific solution based on diagnosis
    if not results["ping_test"]:
        results["solution"] = "network"
        results["solution_text"] = "Cannot reach OpenWrt router. Check: 1) Router is powered on, 2) PC is connected to router network, 3) Router IP is 192.168.1.1"
    elif not results["ssh_test"]:
        results["solution"] = "ssh_failed"
        results["solution_text"] = "SSH connection failed. Check: 1) SSH/Dropbear is enabled on OpenWrt, 2) Try: ssh root@192.168.1.1 in terminal"
    
    return jsonify(results)


@api_bp.route('/time_info')
def api_time_info():
    """Get time information from PC and OpenWrt"""
    info = capture_manager.get_time_info()
    sync_status = capture_manager.time_sync_status
    info["last_sync"] = sync_status["last_sync"].strftime("%Y-%m-%d %H:%M:%S") if sync_status.get("last_sync") else None
    return jsonify(info)


@api_bp.route('/sync_time', methods=['POST'])
def api_sync_time():
    """Manually sync OpenWrt time with PC time"""
    success, message = capture_manager.sync_time()
    info = capture_manager.get_time_info()
    return jsonify({
        "success": success,
        "message": message,
        "time_info": info
    })


@api_bp.route('/file_split', methods=['GET'])
def api_get_file_split():
    """Get current file split configuration"""
    return jsonify({
        "enabled": capture_manager.file_split_config["enabled"],
        "size_mb": capture_manager.file_split_config["size_mb"]
    })


@api_bp.route('/file_split', methods=['POST'])
def api_set_file_split():
    """Update file split configuration"""
    data = request.get_json()
    
    if "enabled" in data:
        capture_manager.file_split_config["enabled"] = bool(data["enabled"])
    
    if "size_mb" in data:
        size = int(data["size_mb"])
        # Validate size (minimum 10MB, maximum 2000MB)
        if size < 10:
            size = 10
        elif size > 2000:
            size = 2000
        capture_manager.file_split_config["size_mb"] = size
    
    return jsonify({
        "success": True,
        "enabled": capture_manager.file_split_config["enabled"],
        "size_mb": capture_manager.file_split_config["size_mb"],
        "message": f"File split {'enabled' if capture_manager.file_split_config['enabled'] else 'disabled'}" + 
                   (f" ({capture_manager.file_split_config['size_mb']}MB per file)" if capture_manager.file_split_config['enabled'] else "")
    })


@api_bp.route('/interface_mapping')
def api_get_interface_mapping():
    """Get current interface mapping and detection status"""
    detection = capture_manager.detection_status
    return jsonify({
        "interfaces": capture_manager.interfaces,
        "uci_wifi_map": capture_manager.uci_wifi_map,
        "detection_status": {
            "detected": detection["detected"],
            "last_detection": detection["last_detection"].strftime("%Y-%m-%d %H:%M:%S") if detection.get("last_detection") else None,
            "detection_method": detection.get("detection_method"),
            "detected_mapping": detection.get("detected_mapping")
        }
    })


@api_bp.route('/detect_interfaces', methods=['POST'])
def api_detect_interfaces():
    """Force re-detection of interface mapping"""
    # Reset detection status to force re-detection
    capture_manager.detection_status["detected"] = False
    
    # Run detection
    success = capture_manager.detect_interfaces()
    
    detection = capture_manager.detection_status
    return jsonify({
        "success": success,
        "interfaces": capture_manager.interfaces,
        "uci_wifi_map": capture_manager.uci_wifi_map,
        "detection_status": {
            "detected": detection["detected"],
            "last_detection": detection["last_detection"].strftime("%Y-%m-%d %H:%M:%S") if detection.get("last_detection") else None,
            "detection_method": detection.get("detection_method")
        },
        "message": f"Detection {'successful' if success else 'failed'}. Mapping: 2G={capture_manager.interfaces.get('2G')}, 5G={capture_manager.interfaces.get('5G')}, 6G={capture_manager.interfaces.get('6G')}"
    })
