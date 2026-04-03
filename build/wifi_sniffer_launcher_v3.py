"""
WiFi Sniffer Windows Launcher v3
================================
Lightweight packaged entry point for the v3 web control panel.
Designed for stable PyInstaller builds on Windows.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wifi_sniffer_v3 as app_module
from wifi_sniffer_v3.config import DEBUG_MODE, SERVER_HOST, SERVER_PORT, VERSION


def _display_host() -> str:
    return "127.0.0.1" if SERVER_HOST == "0.0.0.0" else SERVER_HOST


def _show_error_message(message: str) -> None:
    if sys.platform == "win32":
        try:
            ctypes.windll.user32.MessageBoxW(0, message, "WiFi Sniffer Startup Error", 0x10)
            return
        except Exception:
            pass
    print(message)


def _open_browser_when_ready(host: str, port: int) -> None:
    time.sleep(2)
    try:
        webbrowser.open(f"http://{host}:{port}")
    except Exception:
        pass


def main():
    try:
        app = app_module.create_app()
        host = _display_host()
        port = int(os.environ.get("FLASK_PORT", SERVER_PORT))

        threading.Thread(
            target=_open_browser_when_ready,
            args=(host, port),
            daemon=True,
        ).start()

        if app_module.is_socketio_enabled() and app_module.socketio is not None:
            app_module.socketio.run(
                app,
                host=SERVER_HOST,
                port=port,
                debug=DEBUG_MODE,
                use_reloader=False,
                allow_unsafe_werkzeug=True,
            )
        else:
            app.run(
                host=SERVER_HOST,
                port=port,
                debug=DEBUG_MODE,
                use_reloader=False,
                threaded=True,
            )
    except Exception as exc:
        _show_error_message(
            "WiFi Sniffer failed to start.\n\n"
            f"Error: {exc}\n\n"
            "If LOG_FILE is configured, check the log for details."
        )
        raise


if __name__ == "__main__":
    main()
