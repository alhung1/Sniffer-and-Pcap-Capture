"""
View Routes v4
==============
Page rendering — fast async-first approach.
"""

from flask import current_app, render_template

from . import views_bp
from ..config import CHANNELS, BANDWIDTHS, DOWNLOADS_FOLDER


@views_bp.route("/")
def index():
    """Main page – connection tested via AJAX (no blocking)."""
    iface = current_app.extensions["interface_service"]
    cap = current_app.extensions["capture_service"]
    wifi = current_app.extensions["wifi_config_service"]

    status = cap.get_all_status()
    det = iface.detection_status

    return render_template(
        "index_v4.html",
        connected=None,
        status=status,
        channels=CHANNELS,
        bandwidths=BANDWIDTHS,
        channel_config=wifi.channel_config,
        download_path=DOWNLOADS_FOLDER,
        interfaces=iface.interfaces,
        uci_wifi_map=iface.uci_wifi_map,
        detection_status={
            "detected": det["detected"],
            "method": det["detection_method"],
            "last_detection": det["last_detection"].strftime("%Y-%m-%d %H:%M:%S") if det["last_detection"] else None,
        },
    )
