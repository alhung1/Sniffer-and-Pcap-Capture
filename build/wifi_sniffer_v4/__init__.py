"""
WiFi Sniffer Web Control Panel v4
==================================
Flask application factory with service-oriented architecture.

Key v4 improvements:
- No paramiko dependency
- SSH availability pre-check
- Semaphore-based concurrency (not mutex)
- Persistent config (channel, file-split)
- Real file-size monitoring
- Input validation on all API endpoints
- Localhost-only by default
"""

import logging
import os
import sys

from flask import Flask

from .logging_config import setup_logging

logger = logging.getLogger(__name__)

# Module-level state
socketio = None
_socketio_enabled = False
_startup_cleanup_done = False

# Service singletons (populated by create_app)
interface_service = None
time_sync_service = None
wifi_config_service = None
capture_service = None


def create_app():
    """Application factory."""
    global socketio, _socketio_enabled
    global interface_service, time_sync_service, wifi_config_service, capture_service

    setup_logging(
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        log_file=os.environ.get("LOG_FILE"),
    )

    # PyInstaller bundle support
    if getattr(sys, "frozen", False):
        base_dir = sys._MEIPASS
        logger.info("Running as bundled exe, base_dir=%s", base_dir)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        logger.info("Running from source, base_dir=%s", base_dir)

    template_folder = os.path.join(base_dir, "templates")
    static_folder = os.path.join(base_dir, "wifi_sniffer_v4", "static")
    if not os.path.exists(static_folder):
        static_folder = os.path.join(base_dir, "static")

    logger.info("Templates: %s | Static: %s", template_folder, static_folder)

    from .config import SECRET_KEY
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    app.config["SECRET_KEY"] = SECRET_KEY

    # SocketIO
    socketio, _socketio_enabled = _init_socketio(app)

    # Services
    from .services import InterfaceService, TimeSyncService, WifiConfigService, CaptureService

    interface_service = InterfaceService()
    time_sync_service = TimeSyncService()
    wifi_config_service = WifiConfigService(interface_service)
    capture_service = CaptureService(interface_service, time_sync_service, wifi_config_service)

    app.extensions["interface_service"] = interface_service
    app.extensions["time_sync_service"] = time_sync_service
    app.extensions["wifi_config_service"] = wifi_config_service
    app.extensions["capture_service"] = capture_service

    # Blueprints
    from .routes import api_bp, views_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(views_bp)

    # SocketIO events
    if _socketio_enabled and socketio:
        capture_service.set_socketio(socketio)
        _register_socketio_events()
    else:
        logger.info("SocketIO disabled – polling mode")

    # Log SSH status
    from .ssh import ssh_client
    if not ssh_client.is_available:
        logger.warning("SSH NOT AVAILABLE — capture will not work until SSH is installed")

    return app


def _init_socketio(app):
    try:
        from flask_socketio import SocketIO
    except ImportError:
        logger.warning("flask-socketio not installed — polling mode only")
        return None, False

    for mode in ("threading", "eventlet", "gevent", None):
        try:
            logger.info("Trying SocketIO async_mode='%s'...", mode)
            sio = SocketIO()
            sio.init_app(app, async_mode=mode, cors_allowed_origins="*")
            logger.info("SocketIO OK with async_mode='%s'", mode)
            return sio, True
        except Exception as e:
            logger.warning("async_mode='%s' failed: %s", mode, e)

    logger.warning("All SocketIO modes failed — falling back to polling")
    return None, False


def _register_socketio_events():
    if not socketio or not _socketio_enabled:
        return

    @socketio.on("connect")
    def handle_connect():
        logger.debug("WebSocket client connected")
        socketio.emit("status_update", capture_service.get_all_status())

    @socketio.on("disconnect")
    def handle_disconnect():
        logger.debug("WebSocket client disconnected")

    @socketio.on("request_status")
    def handle_request_status():
        socketio.emit("status_update", capture_service.get_all_status())

    @socketio.on("request_connection")
    def handle_request_connection():
        global _startup_cleanup_done
        from .ssh import ssh_client
        connected = ssh_client.test_connection()
        if connected:
            if not _startup_cleanup_done:
                logger.info("First connection – startup cleanup")
                capture_service.cleanup_remote_processes()
                _startup_cleanup_done = True
            if not interface_service.detection_status["detected"]:
                interface_service.detect_interfaces()
                wifi_config_service.sync_channel_config_from_openwrt()

        socketio.emit("connection_update", {
            "connected": connected,
            "interfaces": interface_service.interfaces,
            "detection_status": interface_service.detection_status,
        })


# ------------------------------------------------------------------
# Public helpers
# ------------------------------------------------------------------

def broadcast_status_update():
    if socketio and _socketio_enabled:
        try:
            socketio.emit("status_update", capture_service.get_all_status())
        except Exception:
            pass


def broadcast_connection_update(connected: bool):
    if socketio and _socketio_enabled:
        try:
            socketio.emit("connection_update", {
                "connected": connected,
                "interfaces": interface_service.interfaces,
                "detection_status": interface_service.detection_status,
            })
        except Exception:
            pass


def is_socketio_enabled():
    return _socketio_enabled


def perform_startup_cleanup():
    global _startup_cleanup_done
    if _startup_cleanup_done:
        return False
    ok, msg = capture_service.cleanup_remote_processes()
    _startup_cleanup_done = True
    logger.info("Startup cleanup: %s", msg)
    return ok


def is_startup_cleanup_done():
    return _startup_cleanup_done
