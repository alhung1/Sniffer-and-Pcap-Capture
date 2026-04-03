from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from wifi_sniffer_v3.cache import get_cached_connection_status, set_cached_connection_status
from wifi_sniffer_v3.config import ConfigError, load_config, validate_runtime_config
from wifi_sniffer_v3.remote import (
    RemoteCommandError,
    build_cleanup_stale_captures_command,
    build_start_capture_command,
    make_capture_paths,
    validate_band,
    validate_interface,
)
from wifi_sniffer_v3.services.capture import CaptureService
from wifi_sniffer_v3.services.interfaces import InterfaceService
from wifi_sniffer_v3.services.time_sync import TimeSyncService
from wifi_sniffer_v3.services.wifi_config import WifiConfigService


def test_load_config_reads_overrides_without_requiring_reload():
    with patch.dict(
        os.environ,
        {
            "OPENWRT_HOST": "10.0.0.1",
            "OPENWRT_USER": "admin",
            "SSH_PORT": "2222",
            "MONITOR_INTERVAL": "7",
            "FLASK_DEBUG": "true",
        },
        clear=False,
    ):
        config = load_config()

    assert config.openwrt_host == "10.0.0.1"
    assert config.openwrt_user == "admin"
    assert config.ssh_port == 2222
    assert config.monitor_interval == 7
    assert config.debug_mode is True


def test_validate_runtime_config_rejects_missing_ssh_key():
    with patch.dict(os.environ, {"SSH_KEY_PATH": str(Path("does-not-exist.key"))}, clear=False):
        config = load_config()

    with pytest.raises(ConfigError):
        validate_runtime_config(config)


def test_validate_band_normalizes_case():
    assert validate_band("5g") == "5G"


def test_validate_interface_rejects_unexpected_names():
    with pytest.raises(RemoteCommandError):
        validate_interface("ath0; rm -rf /")


def test_make_capture_paths_requires_safe_session_id():
    with pytest.raises(RemoteCommandError):
        make_capture_paths("2G", "bad/session")


def test_build_start_capture_command_uses_pid_file_and_quotes_paths():
    paths = make_capture_paths("2G", "abc123def456")
    command = build_start_capture_command("ath0", paths, split_size_mb=200)

    assert paths.remote_pid_path in command
    assert "tcpdump" in command
    assert "-C 200" in command
    assert "TCPDUMP_STARTED" in command


def test_cleanup_command_targets_only_app_prefix():
    command = build_cleanup_stale_captures_command()

    assert "killall tcpdump" not in command
    assert "rm -f /tmp/*.pcap" not in command
    assert "wifi_sniffer_capture_" in command


def test_connection_cache_payload_round_trip():
    payload = {
        "connected": True,
        "host": "192.168.1.1",
        "port": 22,
        "user": "root",
        "auth_method": "publickey",
        "error": None,
    }
    set_cached_connection_status(payload)

    cached = get_cached_connection_status()
    assert cached == payload
    assert cached["auth_method"] == "publickey"


def test_capture_service_tracks_session_and_prevents_duplicate_start():
    iface = InterfaceService()
    wifi = WifiConfigService(iface)
    capture = CaptureService(iface, TimeSyncService(), wifi)

    with patch("wifi_sniffer_v3.services.capture.run_ssh_command", return_value=(True, "TCPDUMP_STARTED\n", "")), patch(
        "threading.Thread.start", return_value=None
    ):
        ok, _ = capture.start_capture("2G", auto_sync_time=False)
        duplicate_ok, duplicate_msg = capture.start_capture("2G", auto_sync_time=False)

    assert ok is True
    assert duplicate_ok is False
    assert "already running" in duplicate_msg

    status = capture.get_status("2G")
    assert status["running"] is True
    assert status["session_id"] is not None
    assert status["state"] == "running"


def test_stop_capture_downloads_using_same_session_id():
    iface = InterfaceService()
    wifi = WifiConfigService(iface)
    capture = CaptureService(iface, TimeSyncService(), wifi)

    with patch("wifi_sniffer_v3.services.capture.run_ssh_command", return_value=(True, "TCPDUMP_STARTED\n", "")), patch(
        "threading.Thread.start", return_value=None
    ):
        ok, _ = capture.start_capture("5G", auto_sync_time=False)

    assert ok is True
    session_id = capture.get_status("5G")["session_id"]

    with patch("wifi_sniffer_v3.services.capture.run_ssh_command", return_value=(True, "", "")), patch.object(
        capture._downloader,
        "download_pcap_files",
        return_value=(True, "Saved", "C:\\temp\\5G_sniffer_test.pcap"),
    ) as mock_download:
        ok, msg, path = capture.stop_capture("5G")

    assert ok is True
    assert msg == "Saved"
    assert path.endswith(".pcap")
    mock_download.assert_called_once()
    assert mock_download.call_args.args[2] == session_id
    assert capture.get_status("5G")["running"] is False


def test_api_rejects_invalid_channel_and_bad_boolean():
    from wifi_sniffer_v3 import create_app

    app = create_app()
    client = app.test_client()

    resp = client.post("/api/config/2G", json={"channel": 999, "bandwidth": "HT40"})
    assert resp.status_code == 400
    assert resp.get_json()["success"] is False

    resp = client.post("/api/file_split", json={"enabled": "maybe"})
    assert resp.status_code == 400
    assert resp.get_json()["success"] is False
