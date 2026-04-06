"""
WiFi Sniffer Desktop Application v4
===================================
Professional desktop application with system tray support.
Uses the v4 service-oriented architecture.
No paramiko — native OpenSSH only.

Version: 4.0
"""

import sys
import os
import threading
import webbrowser
import time
import ctypes
from pathlib import Path

# Add parent directory to path for importing the main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import pystray for system tray support
try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    print("[WARNING] pystray or PIL not installed. System tray disabled.")
    print("         Install with: pip install pystray pillow")

# Import v4 modules
try:
    from wifi_sniffer_v4 import create_app, socketio, is_socketio_enabled
    from wifi_sniffer_v4.config import SERVER_PORT, DOWNLOADS_FOLDER, VERSION
except ImportError as e:
    print(f"[ERROR] Import error: {e}")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from wifi_sniffer_v4 import create_app, socketio, is_socketio_enabled
    from wifi_sniffer_v4.config import SERVER_PORT, DOWNLOADS_FOLDER, VERSION


class WiFiSnifferAppV4:
    """Main application class with system tray support - v4"""

    def __init__(self):
        self.server_thread = None
        self.server_running = False
        self.icon = None
        self.app = None
        self.port = int(os.environ.get('FLASK_PORT', SERVER_PORT))
        self.host = "127.0.0.1"

    def create_icon_image(self, color="green"):
        """Create a simple icon image for the system tray"""
        size = 64
        image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)

        if color == "green":
            main_color = (34, 197, 94, 255)
        elif color == "red":
            main_color = (239, 68, 68, 255)
        elif color == "yellow":
            main_color = (245, 158, 11, 255)
        else:
            main_color = (148, 163, 184, 255)

        center_x, center_y = size // 2, size - 10
        for radius in [12, 22, 32]:
            bbox = [
                center_x - radius, center_y - radius,
                center_x + radius, center_y + radius
            ]
            draw.arc(bbox, 200, 340, fill=main_color, width=4)

        dot_radius = 5
        draw.ellipse([
            center_x - dot_radius, center_y - dot_radius,
            center_x + dot_radius, center_y + dot_radius
        ], fill=main_color)

        return image

    def get_status_text(self):
        """Get current capture status as text"""
        try:
            cap = self.app.extensions.get("capture_service")
            if cap:
                status = cap.get_all_status()
                running = [b for b in ("2G", "5G", "6G") if status[b]["running"]]
                if running:
                    return f"Capturing: {', '.join(running)}"
        except Exception:
            pass
        return "Idle"

    def open_browser(self, icon=None, item=None):
        url = f"http://{self.host}:{self.port}"
        webbrowser.open(url)

    def open_downloads(self, icon=None, item=None):
        try:
            os.startfile(DOWNLOADS_FOLDER)
        except Exception:
            pass

    def show_status(self, icon=None, item=None):
        status = self.get_status_text()
        try:
            from wifi_sniffer_v4.ssh import ssh_client
            connected = "Connected" if ssh_client.test_connection() else "Disconnected"
        except Exception:
            connected = "Unknown"

        message = (
            f"WiFi Sniffer Control Panel v{VERSION}\n\n"
            f"Server: http://{self.host}:{self.port}\n"
            f"Router: {connected}\n"
            f"Status: {status}\n"
            f"\nDownload folder:\n{DOWNLOADS_FOLDER}"
        )
        ctypes.windll.user32.MessageBoxW(0, message, "WiFi Sniffer Status", 0x40)

    def quit_app(self, icon=None, item=None):
        self.server_running = False
        if self.icon:
            self.icon.stop()
        os._exit(0)

    def update_icon(self):
        if not self.icon or not TRAY_AVAILABLE:
            return
        try:
            cap = self.app.extensions.get("capture_service")
            if cap:
                status = cap.get_all_status()
                any_running = any(status[b]["running"] for b in ("2G", "5G", "6G"))
                self.icon.icon = self.create_icon_image("yellow" if any_running else "green")
        except Exception:
            pass

    def status_monitor(self):
        while self.server_running:
            try:
                self.update_icon()
            except Exception:
                pass
            time.sleep(3)

    def run_server(self):
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        try:
            if is_socketio_enabled() and socketio is not None:
                print("[INFO] Starting server with SocketIO...")
                socketio.run(
                    self.app,
                    host=self.host,
                    port=self.port,
                    debug=False,
                    use_reloader=False,
                    allow_unsafe_werkzeug=True
                )
            else:
                print("[INFO] Starting server without SocketIO (polling mode)...")
                self.app.run(
                    host=self.host,
                    port=self.port,
                    debug=False,
                    use_reloader=False,
                    threaded=True
                )
        except Exception as e:
            print(f"[ERROR] Server error: {e}")
            import traceback
            traceback.print_exc()
            self.server_running = False

    def create_menu(self):
        return pystray.Menu(
            item('Open Web Panel', self.open_browser, default=True),
            item('Open Downloads', self.open_downloads),
            pystray.Menu.SEPARATOR,
            item('Status', self.show_status),
            pystray.Menu.SEPARATOR,
            item('Exit', self.quit_app)
        )

    def run(self):
        print("=" * 60)
        print(f"  WiFi Sniffer Desktop Application v{VERSION}")
        print("=" * 60)
        print(f"  Server: http://{self.host}:{self.port}")
        print(f"  Downloads: {DOWNLOADS_FOLDER}")
        print("-" * 60)

        print("[INFO] Creating Flask application...")
        self.app = create_app()
        print("[OK] Flask application created")

        self.server_running = True

        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()

        time.sleep(2)
        self.open_browser()

        if TRAY_AVAILABLE:
            print("[INFO] System tray enabled. Right-click the icon for options.")

            monitor_thread = threading.Thread(target=self.status_monitor, daemon=True)
            monitor_thread.start()

            self.icon = pystray.Icon(
                "WiFi Sniffer v4",
                self.create_icon_image("green"),
                f"WiFi Sniffer Control Panel v{VERSION}",
                self.create_menu()
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
    if sys.platform == 'win32':
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(f"WiFi Sniffer Control Panel v{VERSION}")
        except Exception:
            pass

    app_instance = WiFiSnifferAppV4()
    app_instance.run()


if __name__ == '__main__':
    main()
