"""
WiFi Sniffer Web Control Panel v3 - Entry Point
================================================
Starts the Flask + SocketIO server using the modular v3 architecture.

Usage:
    python wifi_sniffer_web_control_v3.py
"""

import os
import sys

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wifi_sniffer_v3 import create_app, socketio, is_socketio_enabled
from wifi_sniffer_v3.config import SERVER_PORT, SERVER_HOST, DEBUG_MODE, VERSION


def main():
    app = create_app()

    display_host = "127.0.0.1" if SERVER_HOST == "0.0.0.0" else SERVER_HOST

    print("=" * 60)
    print(f"  WiFi Sniffer Web Control Panel  v{VERSION}")
    print("=" * 60)
    print(f"  URL   : http://{display_host}:{SERVER_PORT}")
    print(f"  Debug : {DEBUG_MODE}")
    print(f"  SIO   : {is_socketio_enabled()}")
    print("-" * 60)

    if is_socketio_enabled() and socketio is not None:
        socketio.run(
            app,
            host=SERVER_HOST,
            port=SERVER_PORT,
            debug=DEBUG_MODE,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
        )
    else:
        app.run(
            host=SERVER_HOST,
            port=SERVER_PORT,
            debug=DEBUG_MODE,
            use_reloader=False,
            threaded=True,
        )


if __name__ == "__main__":
    main()
