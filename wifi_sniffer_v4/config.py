"""
WiFi Sniffer Configuration v4
==============================
Environment-aware, with persistent user config.
"""

import json
import logging
import os
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

# Lock to prevent concurrent read-modify-write on config.json
_config_lock = threading.Lock()

# ============== Version ==============
VERSION = "4.0"

# ============== Persistent Config File ==============
_CONFIG_DIR = Path.home() / ".wifi_sniffer"
_CONFIG_FILE = _CONFIG_DIR / "config.json"

# ============== OpenWrt Configuration ==============
OPENWRT_HOST = os.environ.get("OPENWRT_HOST", "192.168.1.1")
OPENWRT_USER = os.environ.get("OPENWRT_USER", "root")
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", None)
SSH_PORT = int(os.environ.get("SSH_PORT", 22))

# ============== Interface Mapping ==============
DEFAULT_INTERFACES = {
    "2G": "ath0",
    "5G": "ath2",
    "6G": "ath1",
}

DEFAULT_UCI_WIFI_MAP = {
    "2G": "wifi0",
    "5G": "wifi2",
    "6G": "wifi1",
}

# ============== Download Configuration ==============
DOWNLOADS_FOLDER = os.environ.get(
    "SNIFFER_DOWNLOADS", str(Path.home() / "Downloads")
)

# ============== Server Configuration ==============
SERVER_PORT = int(os.environ.get("FLASK_PORT", 5000))
# v4: default to 127.0.0.1 for security (localhost only)
SERVER_HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
DEBUG_MODE = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# SECRET_KEY: random per-process (never hardcoded)
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

# ============== Capture Info (Product / SW Version) ==============
DEFAULT_PRODUCT_NAME = ""
DEFAULT_SW_VERSION = ""
# Filename-safe pattern: alphanumeric, dot, underscore, hyphen; 1-30 chars
CAPTURE_INFO_PATTERN = r"^[a-zA-Z0-9._-]{1,30}$"

# ============== Cache / Monitor ==============
CONNECTION_CACHE_TTL = 10
INTERFACE_CACHE_TTL = 300
STATUS_UPDATE_INTERVAL = 3
MONITOR_INTERVAL = 5
MONITOR_ERROR_THRESHOLD = 3

# ============== SSH Configuration ==============
SSH_CONNECT_TIMEOUT = 10
SSH_COMMAND_TIMEOUT = 30
SSH_MAX_CONCURRENT = 4  # v4: semaphore limit instead of mutex


# ============== Persistent Config Helpers ==============

def load_persistent_config() -> dict:
    """Load user config from ~/.wifi_sniffer/config.json (thread-safe)."""
    with _config_lock:
        try:
            if _CONFIG_FILE.exists():
                with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    logger.info("Loaded persistent config from %s", _CONFIG_FILE)
                    return data
        except Exception as e:
            logger.warning("Failed to load persistent config: %s", e)
        return {}


def save_persistent_config(data: dict) -> bool:
    """Save user config to ~/.wifi_sniffer/config.json (thread-safe)."""
    with _config_lock:
        try:
            _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            # Write to temp file then rename for atomicity
            tmp_file = _CONFIG_FILE.with_suffix(".tmp")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            tmp_file.replace(_CONFIG_FILE)
            logger.info("Saved persistent config to %s", _CONFIG_FILE)
            return True
        except Exception as e:
            logger.warning("Failed to save persistent config: %s", e)
            return False
