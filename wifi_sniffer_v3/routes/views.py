"""
View Routes
===========
Page rendering routes for the WiFi Sniffer v3 application.
"""

from flask import current_app, render_template

from . import views_bp
from ..config import CHANNELS, BANDWIDTHS, DOWNLOADS_FOLDER


@views_bp.route("/")
def index():
    """Render the main page. Connection check happens via AJAX."""
    iface_svc = current_app.extensions["interface_service"]
    cap_svc = current_app.extensions["capture_service"]
    wifi_svc = current_app.extensions["wifi_config_service"]

    det = iface_svc.detection_status
    detection_status = {
        "detected": det["detected"],
        "method": det["detection_method"],
        "last_detection": (
            det["last_detection"].strftime("%Y-%m-%d %H:%M:%S")
            if det["last_detection"] else None
        ),
    }

    return render_template(
        "index.html",
        connected=None,
        status=cap_svc.get_all_status(),
        channels=CHANNELS,
        bandwidths=BANDWIDTHS,
        channel_config=wifi_svc.channel_config,
        download_path=DOWNLOADS_FOLDER,
        interfaces=iface_svc.interfaces,
        uci_wifi_map=iface_svc.uci_wifi_map,
        detection_status=detection_status,
    )
