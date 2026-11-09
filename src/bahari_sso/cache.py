"""A pluggable cache protocol (discovery, JWKS, machine tokens, sign-in state) and an in-memory default."""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Dict, Optional, Tuple

try:
    from typing import Protocol
except ImportError:  # pragma: no cover
    from typing_extensions import Protocol  # type: ignore

__all__ = ["Cache", "MemoryCache"]


class Cache(Protocol):
    """Values are JSON-serialisable (dicts, lists, strings, numbers, booleans). ``ttl`` is in seconds.

    Optionally implement ``add(key, value, ttl) -> bool`` (store only when absent, atomically); it is used to
    de-duplicate back-channel logout notifications across processes.
    """

    def get(self, key: str) -> Any: ...

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None: ...

    def delete(self, key: str) -> None: ...


class MemoryCache:
    """Thread-safe per-process cache. Use a shared cache (Redis, memcached, database) when running several workers."""

    def __init__(self) -> None:
        self._items: Dict[str, Tuple[Any, Optional[float]]] = {}
        self._lock = threading.Lock()

    def _live(self, key: str) -> bool:
        item = self._items.get(key)
        if item is None:
            return False
        if item[1] is not None and item[1] <= time.time():
            del self._items[key]
            return False
        return True

    def get(self, key: str) -> Any:
        with self._lock:
            return copy.deepcopy(self._items[key][0]) if self._live(key) else None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        with self._lock:
            self._items[key] = (copy.deepcopy(value), None if ttl is None else time.time() + ttl)

    def add(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        with self._lock:
            if self._live(key):
                return False
            self._items[key] = (copy.deepcopy(value), None if ttl is None else time.time() + ttl)
            return True

    def delete(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
