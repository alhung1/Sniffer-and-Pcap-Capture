"""
Cache Layer
===========
Thread-safe TTL cache for expensive operations.
"""

import threading
import time
from typing import Any, Callable, Optional

from .config import CONNECTION_CACHE_TTL, INTERFACE_CACHE_TTL


class _CacheEntry:
    __slots__ = ("value", "created_at", "ttl")

    def __init__(self, value: Any, ttl: float):
        self.value = value
        self.created_at = time.monotonic()
        self.ttl = ttl

    def is_valid(self) -> bool:
        return (time.monotonic() - self.created_at) < self.ttl


class StatusCache:
    """Singleton TTL cache with thread-safe access."""

    _instance = None
    _init_lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._store: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()
        self._ttl_defaults: dict[str, float] = {
            "connection_status": CONNECTION_CACHE_TTL,
            "interface_mapping": INTERFACE_CACHE_TTL,
            "wifi_config": 60,
            "time_info": 2,
        }
        self._initialized = True

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry and entry.is_valid():
                return entry.value
            return None

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        if ttl is None:
            ttl = self._ttl_defaults.get(key, 30)
        with self._lock:
            self._store[key] = _CacheEntry(value, ttl)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def invalidate_all(self) -> None:
        with self._lock:
            self._store.clear()

    def get_or_compute(self, key: str, fn: Callable, ttl: Optional[float] = None) -> Any:
        cached = self.get(key)
        if cached is not None:
            return cached
        value = fn()
        self.set(key, value, ttl)
        return value


# Global singleton
status_cache = StatusCache()
