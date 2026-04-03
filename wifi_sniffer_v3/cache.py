"""
Cache Layer
===========
TTL-based caching for expensive operations.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional, TypedDict

from .config import CONNECTION_CACHE_TTL, INTERFACE_CACHE_TTL

_SENTINEL = object()


class ConnectionStatusPayload(TypedDict):
    connected: bool
    host: str
    port: int
    user: str
    auth_method: str
    error: Optional[str]


class InterfaceMappingPayload(TypedDict):
    interfaces: dict[str, str]
    uci_wifi_map: dict[str, str]
    detection_status: dict[str, Any]


class CacheEntry:
    """Single cache entry with TTL."""

    __slots__ = ("value", "created_at", "ttl")

    def __init__(self, value: Any, ttl: float):
        self.value = value
        self.created_at = time.time()
        self.ttl = ttl

    def is_valid(self) -> bool:
        return time.time() - self.created_at < self.ttl


class StatusCache:
    """
    Thread-safe, TTL-based cache.

    Uses a singleton so every module shares the same store.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._cache: dict[str, CacheEntry] = {}
        self._cache_lock = threading.Lock()

        self._ttl_settings: dict[str, float] = {
            "connection_status": CONNECTION_CACHE_TTL,
            "interface_mapping": INTERFACE_CACHE_TTL,
            "wifi_config": 60,
            "time_info": 2,
        }
        self._initialized = True

    def get(self, key: str) -> Any:
        """Return cached value if valid, otherwise ``_SENTINEL``."""
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry and entry.is_valid():
                return entry.value
            return _SENTINEL

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        if ttl is None:
            ttl = self._ttl_settings.get(key, 30)
        with self._cache_lock:
            self._cache[key] = CacheEntry(value, ttl)

    def invalidate(self, key: str) -> None:
        with self._cache_lock:
            self._cache.pop(key, None)

    def invalidate_all(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    def get_or_compute(
        self,
        key: str,
        compute_fn: Callable[[], Any],
        ttl: Optional[float] = None,
    ) -> Any:
        """
        Return cached value or compute, cache, and return.

        Unlike v2 this uses a sentinel so ``None`` and ``False``
        are valid cached values.
        """
        cached = self.get(key)
        if cached is not _SENTINEL:
            return cached
        value = compute_fn()
        self.set(key, value, ttl)
        return value


# Global singleton
status_cache = StatusCache()


def get_cached_connection_status() -> Optional[ConnectionStatusPayload]:
    """Return the cached connection-status payload, or ``None`` if expired."""
    result = status_cache.get("connection_status")
    return None if result is _SENTINEL else result


def set_cached_connection_status(result: ConnectionStatusPayload) -> None:
    """Cache the full connection-status payload."""
    status_cache.set("connection_status", result)


def get_cached_interface_mapping() -> Optional[InterfaceMappingPayload]:
    result = status_cache.get("interface_mapping")
    return None if result is _SENTINEL else result


def set_cached_interface_mapping(mapping: InterfaceMappingPayload) -> None:
    status_cache.set("interface_mapping", mapping)


def invalidate_connection_cache() -> None:
    status_cache.invalidate("connection_status")
    status_cache.invalidate("interface_mapping")
