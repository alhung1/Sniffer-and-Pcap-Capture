"""
WiFi Sniffer Desktop Application v3
===================================
System-tray desktop wrapper for the v3 modular architecture.

Version: 3.0
"""

import ctypes
import logging
import os
import sys
import threading
import time
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    print("[WARNING] pystray or PIL not installed. System tray disabled.")

from wifi_sniffer_v3 import create_app, socketio, is_socketio_enabled
from wifi_sniffer_v3.config import SERVER_PORT, DOWNLOADS_FOLDER, VERSION
from wifi_sniffer_v3.services import CaptureService
from wifi_sniffer_v3.ssh import ssh_client

logger = logging.getLogger(__name__)


class WiFiSnifferAppV3:
    """Desktop application with optional system-tray icon."""

    def __init__(self):
        self.server_thread = None
        self.server_running = False
        self.icon = None
        self.app = None
        self.port = int(os.environ.get("FLASK_PORT", SERVER_PORT))
        self.host = "127.0.0.1"
        self._capture_svc: CaptureService | None = None

    def create_icon_image(self, color="green"):
        size = 64
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)

        colours = {
            "green": (34, 197, 94, 255),
            "red": (239, 68, 68, 255),
            "yellow": (245, 158, 11, 255),
        }
        main = colours.get(color, (148, 163, 184, 255))

        cx, cy = size // 2, size - 10
        for radius in (12, 22, 32):
            bbox = [cx - radius, cy - radius, cx + radius, cy + radius]
            draw.arc(bbox, 200, 340, fill=main, width=4)
        r = 5
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=main)
        return image

    def _status_text(self):
        if not self._capture_svc:
            return "Idle"
        try:
            st = self._capture_svc.get_all_status()
            running = [b for b in ("2G", "5G", "6G") if st[b]["running"]]
            return f"Capturing: {', '.join(running)}" if running else "Idle"
        except Exception:
            return "Idle"

    def open_browser(self, icon=None, item=None):
        webbrowser.open(f"http://{self.host}:{self.port}")

    def open_downloads(self, icon=None, item=None):
        try:
            os.startfile(DOWNLOADS_FOLDER)
        except Exception:
            pass

    def show_status(self, icon=None, item=None):
        try:
            conn = "Connected" if ssh_client.test_connection() else "Disconnected"
        except Exception:
            conn = "Unknown"
        msg = (
            f"WiFi Sniffer Control Panel v{VERSION}\n\n"
            f"Server: http://{self.host}:{self.port}\n"
            f"Router: {conn}\n"
            f"Status: {self._status_text()}\n"
            f"\nDownload folder:\n{DOWNLOADS_FOLDER}"
        )
        ctypes.windll.user32.MessageBoxW(0, msg, "WiFi Sniffer Status", 0x40)

    def quit_app(self, icon=None, item=None):
        self.server_running = False
        if self.icon:
            self.icon.stop()
        os._exit(0)

    def _update_icon(self):
        if not self.icon or not TRAY_AVAILABLE or not self._capture_svc:
            return
        try:
            st = self._capture_svc.get_all_status()
            any_running = any(st[b]["running"] for b in ("2G", "5G", "6G"))
            self.icon.icon = self.create_icon_image("yellow" if any_running else "green")
        except Exception:
            pass

    def _status_monitor(self):
        while self.server_running:
            self._update_icon()
            time.sleep(3)

    def _run_server(self):
        import logging as _logging
        _logging.getLogger("werkzeug").setLevel(_logging.ERROR)
        try:
            if is_socketio_enabled() and socketio is not None:
                socketio.run(self.app, host=self.host, port=self.port,
                             debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
            else:
                self.app.run(host=self.host, port=self.port,
                             debug=False, use_reloader=False, threaded=True)
        except Exception:
            logger.exception("Server error")
            self.server_running = False

    def run(self):
        print("=" * 60)
        print(f"  WiFi Sniffer Desktop Application v{VERSION}")
        print("=" * 60)
        print(f"  Server: http://{self.host}:{self.port}")
        print(f"  Downloads: {DOWNLOADS_FOLDER}")
        print("-" * 60)

        self.app = create_app()
        self._capture_svc = self.app.extensions.get("capture_service")
        self.server_running = True

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        time.sleep(2)
        self.open_browser()

        if TRAY_AVAILABLE:
            threading.Thread(target=self._status_monitor, daemon=True).start()
            self.icon = pystray.Icon(
                "WiFi Sniffer v3",
                self.create_icon_image("green"),
                f"WiFi Sniffer Control Panel v{VERSION}",
                pystray.Menu(
                    item("Open Web Panel", self.open_browser, default=True),
                    item("Open Downloads", self.open_downloads),
                    pystray.Menu.SEPARATOR,
                    item("Status", self.show_status),
                    pystray.Menu.SEPARATOR,
                    item("Exit", self.quit_app),
                ),
            )
            self.icon.run()
        else:
            print("[INFO] Running without system tray. Press Ctrl+C to stop.")
            try:
                while self.server_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[INFO] Shutting down...")
                self.server_running = False


def main():
    if sys.platform == "win32":
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(f"WiFi Sniffer Control Panel v{VERSION}")
        except Exception:
            pass
    WiFiSnifferAppV3().run()


if __name__ == "__main__":
    main()
