"""
WiFi Sniffer v3 – Smoke Tests
==============================
Verifies that all modules import cleanly, the Flask app factory works,
services instantiate correctly, routes are registered, and the cache
behaves as expected.

Run with:
    python -m pytest tests/test_v3_smoke.py -v
    # or simply:
    python tests/test_v3_smoke.py
"""

import os
import sys
import unittest

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ======================================================================
# 1. Import tests
# ======================================================================

class TestImports(unittest.TestCase):
    """Every v3 module must import without raising."""

    def test_import_config(self):
        from wifi_sniffer_v3 import config
        self.assertTrue(hasattr(config, "VERSION"))
        self.assertEqual(config.VERSION, "3.0")

    def test_import_logging_config(self):
        from wifi_sniffer_v3 import logging_config
        self.assertTrue(callable(logging_config.setup_logging))

    def test_import_utils(self):
        from wifi_sniffer_v3 import utils
        self.assertTrue(callable(utils.get_subprocess_startupinfo))

    def test_import_cache(self):
        from wifi_sniffer_v3 import cache
        self.assertTrue(hasattr(cache, "StatusCache"))
        self.assertTrue(hasattr(cache, "status_cache"))

    def test_import_ssh_client(self):
        from wifi_sniffer_v3.ssh.client import SSHClient, SSHError
        self.assertTrue(issubclass(SSHError, Exception))

    def test_import_ssh_commands(self):
        from wifi_sniffer_v3.ssh import commands
        self.assertTrue(callable(commands.run_ssh_command))
        self.assertTrue(callable(commands.download_file))

    def test_import_ssh_package(self):
        from wifi_sniffer_v3 import ssh
        self.assertIn("ssh_client", dir(ssh))
        self.assertIn("SSHError", dir(ssh))

    def test_import_services_interfaces(self):
        from wifi_sniffer_v3.services.interfaces import InterfaceService
        self.assertTrue(callable(InterfaceService))

    def test_import_services_time_sync(self):
        from wifi_sniffer_v3.services.time_sync import TimeSyncService
        self.assertTrue(callable(TimeSyncService))

    def test_import_services_wifi_config(self):
        from wifi_sniffer_v3.services.wifi_config import WifiConfigService
        self.assertTrue(callable(WifiConfigService))

    def test_import_services_file_download(self):
        from wifi_sniffer_v3.services.file_download import FileDownloader
        self.assertTrue(callable(FileDownloader))

    def test_import_services_capture(self):
        from wifi_sniffer_v3.services.capture import CaptureService
        self.assertTrue(callable(CaptureService))

    def test_import_services_package(self):
        from wifi_sniffer_v3 import services
        expected = {"CaptureService", "InterfaceService", "TimeSyncService",
                    "WifiConfigService", "FileDownloader"}
        self.assertTrue(expected.issubset(set(dir(services))))

    def test_import_routes(self):
        from wifi_sniffer_v3.routes import api_bp, views_bp
        self.assertEqual(api_bp.url_prefix, "/api")
        self.assertIsNone(views_bp.url_prefix)


# ======================================================================
# 2. Config tests
# ======================================================================

class TestConfig(unittest.TestCase):

    def test_secret_key_not_hardcoded(self):
        from wifi_sniffer_v3.config import SECRET_KEY
        self.assertNotEqual(SECRET_KEY, "wifi-sniffer-secret-key")
        self.assertTrue(len(SECRET_KEY) > 10)

    def test_debug_mode_default_off(self):
        from wifi_sniffer_v3.config import DEBUG_MODE
        # Without the env var set, DEBUG_MODE should be False
        self.assertFalse(DEBUG_MODE)

    def test_version(self):
        from wifi_sniffer_v3.config import VERSION
        self.assertEqual(VERSION, "3.0")

    def test_channels_structure(self):
        from wifi_sniffer_v3.config import CHANNELS, BANDWIDTHS
        for band in ("2G", "5G", "6G"):
            self.assertIn(band, CHANNELS)
            self.assertIn(band, BANDWIDTHS)
            self.assertIsInstance(CHANNELS[band], list)
            self.assertIsInstance(BANDWIDTHS[band], list)


# ======================================================================
# 3. Cache tests
# ======================================================================

class TestCache(unittest.TestCase):

    def test_set_and_get(self):
        from wifi_sniffer_v3.cache import StatusCache
        c = StatusCache()
        c.set("test_key", {"hello": "world"}, ttl=10)
        self.assertEqual(c.get("test_key"), {"hello": "world"})

    def test_expired_returns_sentinel(self):
        import time
        from wifi_sniffer_v3.cache import StatusCache, _SENTINEL
        c = StatusCache()
        c.set("expire_test", 42, ttl=0.01)
        time.sleep(0.05)
        self.assertIs(c.get("expire_test"), _SENTINEL)

    def test_none_is_valid_cached_value(self):
        from wifi_sniffer_v3.cache import StatusCache, _SENTINEL
        c = StatusCache()
        c.set("none_val", None, ttl=60)
        result = c.get("none_val")
        self.assertIsNone(result)
        self.assertIsNot(result, _SENTINEL)

    def test_convenience_functions_types(self):
        from wifi_sniffer_v3.cache import set_cached_connection_status, get_cached_connection_status
        test_dict = {"connected": True, "host": "1.2.3.4"}
        set_cached_connection_status(test_dict)
        result = get_cached_connection_status()
        self.assertIsInstance(result, dict)
        self.assertEqual(result["host"], "1.2.3.4")

    def test_invalidate(self):
        from wifi_sniffer_v3.cache import StatusCache, _SENTINEL
        c = StatusCache()
        c.set("inv_test", 99, ttl=300)
        c.invalidate("inv_test")
        self.assertIs(c.get("inv_test"), _SENTINEL)


# ======================================================================
# 4. Service instantiation tests
# ======================================================================

class TestServiceInstantiation(unittest.TestCase):

    def test_interface_service(self):
        from wifi_sniffer_v3.services.interfaces import InterfaceService
        svc = InterfaceService()
        self.assertIn("2G", svc.interfaces)
        self.assertIn("5G", svc.interfaces)
        self.assertIn("6G", svc.interfaces)
        self.assertFalse(svc.detection_status["detected"])

    def test_time_sync_service(self):
        from wifi_sniffer_v3.services.time_sync import TimeSyncService
        svc = TimeSyncService()
        self.assertIsNone(svc.status["last_sync"])
        self.assertFalse(svc.status["success"])

    def test_wifi_config_service(self):
        from wifi_sniffer_v3.services.interfaces import InterfaceService
        from wifi_sniffer_v3.services.wifi_config import WifiConfigService
        iface_svc = InterfaceService()
        wifi_svc = WifiConfigService(iface_svc)
        cfg = wifi_svc.get_channel_config()
        self.assertIn("2G", cfg)
        self.assertIn("channel", cfg["2G"])
        self.assertIn("bandwidth", cfg["2G"])

    def test_capture_service(self):
        from wifi_sniffer_v3.services.interfaces import InterfaceService
        from wifi_sniffer_v3.services.time_sync import TimeSyncService
        from wifi_sniffer_v3.services.wifi_config import WifiConfigService
        from wifi_sniffer_v3.services.capture import CaptureService

        iface = InterfaceService()
        ts = TimeSyncService()
        wifi = WifiConfigService(iface)
        cap = CaptureService(iface, ts, wifi)

        all_st = cap.get_all_status()
        for band in ("2G", "5G", "6G"):
            self.assertFalse(all_st[band]["running"])

    def test_file_downloader(self):
        from wifi_sniffer_v3.services.file_download import FileDownloader
        dl = FileDownloader()
        self.assertTrue(callable(dl.download_pcap_files))


# ======================================================================
# 5. App factory & route registration tests
# ======================================================================

class TestAppFactory(unittest.TestCase):

    def setUp(self):
        from wifi_sniffer_v3 import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def test_app_created(self):
        from flask import Flask
        self.assertIsInstance(self.app, Flask)

    def test_extensions_registered(self):
        self.assertIn("capture_service", self.app.extensions)
        self.assertIn("interface_service", self.app.extensions)
        self.assertIn("time_sync_service", self.app.extensions)
        self.assertIn("wifi_config_service", self.app.extensions)

    def test_index_route(self):
        resp = self.client.get("/")
        self.assertIn(resp.status_code, (200, 500))

    def test_api_status_route(self):
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for band in ("2G", "5G", "6G"):
            self.assertIn(band, data)

    def test_api_file_split_get(self):
        resp = self.client.get("/api/file_split")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("enabled", data)
        self.assertIn("size_mb", data)

    def test_api_file_split_post_validation(self):
        resp = self.client.post("/api/file_split", data="not json",
                                content_type="text/plain")
        self.assertEqual(resp.status_code, 400)

    def test_api_config_post_validation(self):
        resp = self.client.post("/api/config/2G", data="bad",
                                content_type="text/plain")
        self.assertEqual(resp.status_code, 400)

    def test_expected_api_endpoints(self):
        rules = [rule.rule for rule in self.app.url_map.iter_rules()]
        expected = [
            "/api/status", "/api/start/<band>", "/api/stop/<band>",
            "/api/start_all", "/api/stop_all",
            "/api/config/<band>", "/api/apply_config",
            "/api/get_wifi_config", "/api/test_connection",
            "/api/diagnose", "/api/time_info", "/api/sync_time",
            "/api/file_split", "/api/interface_mapping",
            "/api/detect_interfaces", "/",
        ]
        for ep in expected:
            self.assertIn(ep, rules, f"Missing route: {ep}")


# ======================================================================
# 6. Utils tests
# ======================================================================

class TestUtils(unittest.TestCase):

    def test_startupinfo_returns_value_on_windows(self):
        from wifi_sniffer_v3.utils import get_subprocess_startupinfo
        result = get_subprocess_startupinfo()
        if sys.platform == "win32":
            self.assertIsNotNone(result)
        else:
            self.assertIsNone(result)


# ======================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
