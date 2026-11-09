"""Small TTL cache implementations for registration-data responses.

The cache API intentionally accepts JSON-serializable values only. Registration
data clients usually receive dictionaries or dataclass-like records; keeping the
cache value simple avoids surprising object-graph serialization problems.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import os
import pathlib
import sqlite3
import threading
import time
from typing import Any, Callable, Protocol


class Cache(Protocol):
    """Minimal cache interface used by callers."""

    def get(self, key: str) -> Any | None: ...

    def set(self, key: str, value: Any, ttl: float | None = None) -> None: ...


@dataclass(frozen=True)
class CacheEntry:
    value: Any
    expires_at: float | None = None

    def expired(self, now: float | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at


def make_key(*parts: Any) -> str:
    return ":".join(str(p).strip() for p in parts if str(p).strip())


def cached(
    cache: Cache | None,
    key: str,
    loader: Callable[[], Any],
    *,
    ttl: float | None = None,
    force_refresh: bool = False,
    should_cache: Callable[[Any], bool] | None = None,
) -> Any:
    if cache is not None and not force_refresh:
        value = cache.get(key)
        if value is not None:
            return value
    value = loader()
    if cache is not None:
        if should_cache is None or should_cache(value):
            cache.set(key, value, ttl=ttl)
    return value


class TTLCache:
    """Thread-safe in-memory TTL cache with optional bounded size."""

    def __init__(
        self, *, default_ttl: float | None = None, max_size: int | None = None
    ) -> None:
        self.default_ttl = default_ttl
        self.max_size = max_size
        self._data: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if entry.expired():
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return entry.value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        if ttl is None:
            ttl = self.default_ttl
        expires_at = None if ttl is None else time.time() + float(ttl)
        with self._lock:
            self._data[key] = CacheEntry(value=value, expires_at=expires_at)
            self._data.move_to_end(key)
            if self.max_size is not None:
                self.prune()
                while len(self._data) > self.max_size:
                    self._data.popitem(last=False)

    def prune(self, *, now: float | None = None) -> int:
        removed = 0
        with self._lock:
            for key in list(self._data.keys()):
                if self._data[key].expired(now):
                    del self._data[key]
                    removed += 1
        return removed

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class JsonFileCache:
    """Simple durable JSON cache, suitable for RDAP/WHOIS response caching."""

    def __init__(
        self,
        cache_dir: str | pathlib.Path,
        *,
        default_ttl: float | None = None,
        namespace: str = "registrata",
    ) -> None:
        self.cache_dir = pathlib.Path(cache_dir) / namespace
        self.default_ttl = default_ttl
        self.namespace = namespace
        self._lock = threading.RLock()

    def path_for(self, key: str) -> pathlib.Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def get(self, key: str) -> Any | None:
        with self._lock:
            path = self.path_for(key)
            if not path.exists():
                return None
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                path.unlink(missing_ok=True)
                return None
            entry = CacheEntry(
                value=payload.get("value"), expires_at=payload.get("expires_at")
            )
            if entry.expired():
                path.unlink(missing_ok=True)
                return None
            return entry.value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        if ttl is None:
            ttl = self.default_ttl
        expires_at = None if ttl is None else time.time() + float(ttl)
        path = self.path_for(key)
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(
                    {"key": key, "expires_at": expires_at, "value": value}, default=str
                ),
                encoding="utf-8",
            )
            os.replace(tmp, path)

    def clear(self) -> int:
        removed = 0
        with self._lock:
            if not self.cache_dir.exists():
                return removed
            for path in self.cache_dir.glob("*.json"):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        return removed


class SQLiteCache:
    """SQLite-backed cache with TTL metadata."""

    def __init__(
        self,
        path: str | pathlib.Path,
        *,
        default_ttl: float | None = None,
        namespace: str = "registrata",
    ) -> None:
        self.path = str(path)
        pathlib.Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self.namespace = namespace
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Create the cache table, adopting pre-rename cache files.

        SQLite files written before the project was renamed to ``registrata`` keep
        their rows in ``pyrwhois_cache``. Renaming that table in place keeps a warm
        cache usable instead of silently discarding it.
        """
        legacy = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pyrwhois_cache'"
        ).fetchone()
        current = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='registrata_cache'"
        ).fetchone()
        if legacy is not None and current is None:
            self._conn.execute("ALTER TABLE pyrwhois_cache RENAME TO registrata_cache")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS registrata_cache (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                expires_at REAL,
                PRIMARY KEY (namespace, key)
            )
            """
        )
        self._conn.commit()

    def get(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT value, expires_at FROM registrata_cache WHERE namespace = ? AND key = ?",
                (self.namespace, key),
            ).fetchone()
            if row is None:
                return None
            value_json, expires_at = row
            if expires_at is not None and now >= float(expires_at):
                self._conn.execute(
                    "DELETE FROM registrata_cache WHERE namespace = ? AND key = ?",
                    (self.namespace, key),
                )
                self._conn.commit()
                return None
            return json.loads(value_json)

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        if ttl is None:
            ttl = self.default_ttl
        expires_at = None if ttl is None else time.time() + float(ttl)
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO registrata_cache(namespace, key, value, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (self.namespace, key, json.dumps(value, default=str), expires_at),
            )
            self._conn.commit()

    def prune(self, *, now: float | None = None) -> int:
        ts = time.time() if now is None else now
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM registrata_cache WHERE namespace = ? AND expires_at IS NOT NULL AND expires_at <= ?",
                (self.namespace, ts),
            )
            self._conn.commit()
            return int(cursor.rowcount or 0)

    def clear(self) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM registrata_cache WHERE namespace = ?", (self.namespace,)
            )
            self._conn.commit()
            return int(cursor.rowcount or 0)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def make_cache(
    backend: str | None,
    *,
    path: str | pathlib.Path | None = None,
    default_ttl: float | None = None,
    namespace: str = "registrata",
    max_size: int = 256,
) -> Cache | None:
    if not backend or backend == "none":
        return None
    normalized = backend.lower()
    if normalized == "memory":
        return TTLCache(default_ttl=default_ttl, max_size=max_size)
    if normalized == "file":
        if path is None:
            raise ValueError("file cache requires path")
        return JsonFileCache(path, default_ttl=default_ttl, namespace=namespace)
    if normalized == "sqlite":
        if path is None:
            raise ValueError("sqlite cache requires path")
        return SQLiteCache(
            pathlib.Path(path) / "registrata_cache.sqlite3",
            default_ttl=default_ttl,
            namespace=namespace,
        )
    raise ValueError(f"unknown cache backend: {backend!r}")


__all__ = [
    "Cache",
    "CacheEntry",
    "JsonFileCache",
    "SQLiteCache",
    "TTLCache",
    "cached",
    "make_cache",
    "make_key",
]
