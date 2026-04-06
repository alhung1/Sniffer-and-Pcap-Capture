"""
WiFi Sniffer Configuration v3
==============================
Environment-aware centralized configuration.
"""

import os
from pathlib import Path

# ============== Version ==============
VERSION = "3.0"

# ============== OpenWrt Configuration ==============
OPENWRT_HOST = os.environ.get("OPENWRT_HOST", "192.168.1.1")
OPENWRT_USER = os.environ.get("OPENWRT_USER", "root")
OPENWRT_PASSWORD = os.environ.get("OPENWRT_PASSWORD", None)
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", None)
SSH_PORT = int(os.environ.get("SSH_PORT", 22))

# ============== Interface Mapping ==============
DEFAULT_INTERFACES = {
    "2G": "ath0",
    "5G": "ath2",
    "6G": "ath1"
}

DEFAULT_UCI_WIFI_MAP = {
    "2G": "wifi0",
    "5G": "wifi2",
    "6G": "wifi1"
}

# ============== Download Configuration ==============
DOWNLOADS_FOLDER = os.environ.get(
    "SNIFFER_DOWNLOADS", str(Path.home() / "Downloads")
)

# ============== Server Configuration ==============
SERVER_PORT = int(os.environ.get("FLASK_PORT", 5000))
# 0.0.0.0 exposes to all interfaces on the network.
# Use 127.0.0.1 to restrict to localhost only.
SERVER_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
DEBUG_MODE = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# SECRET_KEY: use env var if set, otherwise generate a random one per process
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24).hex()

# ============== Channel Configuration ==============
CHANNELS = {
    "2G": list(range(1, 15)),
    "5G": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
           116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165],
    "6G": [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
           65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117,
           121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165,
           169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213,
           217, 221, 225, 229, 233],
}

BANDWIDTHS = {
    "2G": ["HT20", "HT40"],
    "5G": ["EHT20", "EHT40", "EHT80", "EHT160"],
    "6G": ["EHT20", "EHT40", "EHT80", "EHT160", "EHT320"],
}

# ============== Cache Configuration ==============
CONNECTION_CACHE_TTL = 10
INTERFACE_CACHE_TTL = 300
STATUS_UPDATE_INTERVAL = 3

# ============== Monitor Configuration ==============
MONITOR_INTERVAL = 5
MONITOR_ERROR_THRESHOLD = 3

# ============== SSH Configuration ==============
SSH_CONNECT_TIMEOUT = 10
SSH_COMMAND_TIMEOUT = 30
