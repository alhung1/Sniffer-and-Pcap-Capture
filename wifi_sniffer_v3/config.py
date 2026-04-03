"""
WiFi Sniffer Configuration v3
==============================
Environment-aware centralized configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


VERSION = "3.0"

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


class ConfigError(RuntimeError):
    """Raised when runtime configuration is invalid."""


def _parse_env_line(raw_line: str) -> tuple[str, str] | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[7:].strip()
    if "=" not in line:
        return None

    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key:
        return None

    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return key, value


def _load_env_file(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False

    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_env_line(line)
        if parsed is None:
            continue
        key, value = parsed
        os.environ.setdefault(key, value)
    return True


def _load_dotenv_candidates() -> tuple[str, ...]:
    project_root = Path(__file__).resolve().parent.parent
    candidates: list[Path] = []

    for candidate in (Path.cwd() / ".env", project_root / ".env"):
        if candidate not in candidates:
            candidates.append(candidate)

    loaded: list[str] = []
    for candidate in candidates:
        if _load_env_file(candidate):
            loaded.append(str(candidate))
    return tuple(loaded)


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_optional(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _env_int(name: str, default: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value in (None, ""):
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw_value!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw_value = os.environ.get(name)
    if raw_value in (None, ""):
        return default

    normalized = raw_value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw_value!r}")


@dataclass(frozen=True)
class RuntimeConfig:
    version: str
    env_files_loaded: tuple[str, ...]
    openwrt_host: str
    openwrt_user: str
    openwrt_password: str | None
    ssh_key_path: str | None
    ssh_port: int
    downloads_folder: str
    server_port: int
    server_host: str
    debug_mode: bool
    secret_key: str
    log_level: str
    log_file: str | None
    app_remote_prefix: str
    default_interfaces: Mapping[str, str]
    default_uci_wifi_map: Mapping[str, str]
    channels: Mapping[str, list[int]]
    bandwidths: Mapping[str, list[str]]
    connection_cache_ttl: int
    interface_cache_ttl: int
    status_update_interval: int
    monitor_interval: int
    monitor_error_threshold: int
    ssh_connect_timeout: int
    ssh_command_timeout: int


ENV_FILES_LOADED = _load_dotenv_candidates()

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

CHANNELS = {
    "2G": list(range(1, 15)),
    "5G": [
        36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
        116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165,
    ],
    "6G": [
        1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
        65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117,
        121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165,
        169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209, 213,
        217, 221, 225, 229, 233,
    ],
}

BANDWIDTHS = {
    "2G": ["HT20", "HT40"],
    "5G": ["EHT20", "EHT40", "EHT80", "EHT160"],
    "6G": ["EHT20", "EHT40", "EHT80", "EHT160", "EHT320"],
}


def load_config() -> RuntimeConfig:
    secret_key = _env_optional("FLASK_SECRET_KEY") or os.urandom(24).hex()
    downloads_folder = _env_optional("SNIFFER_DOWNLOADS")
    if downloads_folder is None:
        downloads_folder = str(Path.home() / "Downloads")

    return RuntimeConfig(
        version=VERSION,
        env_files_loaded=ENV_FILES_LOADED,
        openwrt_host=_env_str("OPENWRT_HOST", "192.168.1.1"),
        openwrt_user=_env_str("OPENWRT_USER", "root"),
        openwrt_password=_env_optional("OPENWRT_PASSWORD"),
        ssh_key_path=_env_optional("SSH_KEY_PATH"),
        ssh_port=_env_int("SSH_PORT", 22),
        downloads_folder=downloads_folder,
        server_port=_env_int("FLASK_PORT", 5000),
        server_host=_env_str("FLASK_HOST", "0.0.0.0"),
        debug_mode=_env_bool("FLASK_DEBUG", False),
        secret_key=secret_key,
        log_level=_env_str("LOG_LEVEL", "INFO"),
        log_file=_env_optional("LOG_FILE"),
        app_remote_prefix=_env_str("APP_REMOTE_PREFIX", "wifi_sniffer_capture"),
        default_interfaces=DEFAULT_INTERFACES,
        default_uci_wifi_map=DEFAULT_UCI_WIFI_MAP,
        channels=CHANNELS,
        bandwidths=BANDWIDTHS,
        connection_cache_ttl=_env_int("CONNECTION_CACHE_TTL", 10),
        interface_cache_ttl=_env_int("INTERFACE_CACHE_TTL", 300),
        status_update_interval=_env_int("STATUS_UPDATE_INTERVAL", 3),
        monitor_interval=_env_int("MONITOR_INTERVAL", 5),
        monitor_error_threshold=_env_int("MONITOR_ERROR_THRESHOLD", 3),
        ssh_connect_timeout=_env_int("SSH_CONNECT_TIMEOUT", 10),
        ssh_command_timeout=_env_int("SSH_COMMAND_TIMEOUT", 30),
    )


def validate_runtime_config(config: RuntimeConfig) -> None:
    errors: list[str] = []

    if not config.openwrt_host.strip():
        errors.append("OPENWRT_HOST must not be empty")
    if not config.openwrt_user.strip():
        errors.append("OPENWRT_USER must not be empty")
    if not config.server_host.strip():
        errors.append("FLASK_HOST must not be empty")
    if config.ssh_port <= 0 or config.ssh_port > 65535:
        errors.append(f"SSH_PORT must be between 1 and 65535, got {config.ssh_port}")
    if config.server_port <= 0 or config.server_port > 65535:
        errors.append(f"FLASK_PORT must be between 1 and 65535, got {config.server_port}")
    if config.ssh_key_path and not Path(config.ssh_key_path).expanduser().exists():
        errors.append(f"SSH_KEY_PATH does not exist: {config.ssh_key_path}")
    if config.monitor_interval <= 0:
        errors.append("MONITOR_INTERVAL must be > 0")
    if config.monitor_error_threshold <= 0:
        errors.append("MONITOR_ERROR_THRESHOLD must be > 0")

    if errors:
        raise ConfigError("Invalid runtime configuration:\n- " + "\n- ".join(errors))


CONFIG = load_config()
validate_runtime_config(CONFIG)

OPENWRT_HOST = CONFIG.openwrt_host
OPENWRT_USER = CONFIG.openwrt_user
OPENWRT_PASSWORD = CONFIG.openwrt_password
SSH_KEY_PATH = CONFIG.ssh_key_path
SSH_PORT = CONFIG.ssh_port

DOWNLOADS_FOLDER = CONFIG.downloads_folder

SERVER_PORT = CONFIG.server_port
SERVER_HOST = CONFIG.server_host
DEBUG_MODE = CONFIG.debug_mode
SECRET_KEY = CONFIG.secret_key
LOG_LEVEL = CONFIG.log_level
LOG_FILE = CONFIG.log_file
APP_REMOTE_PREFIX = CONFIG.app_remote_prefix

CONNECTION_CACHE_TTL = CONFIG.connection_cache_ttl
INTERFACE_CACHE_TTL = CONFIG.interface_cache_ttl
STATUS_UPDATE_INTERVAL = CONFIG.status_update_interval
MONITOR_INTERVAL = CONFIG.monitor_interval
MONITOR_ERROR_THRESHOLD = CONFIG.monitor_error_threshold
SSH_CONNECT_TIMEOUT = CONFIG.ssh_connect_timeout
SSH_COMMAND_TIMEOUT = CONFIG.ssh_command_timeout
