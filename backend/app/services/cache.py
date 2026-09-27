"""TTL cache backed by Redis/Upstash, degrading to an in-process LRU.

Threat-intel providers rate-limit aggressively (VirusTotal public tier is 4
requests/minute), so every reputation lookup is cached for 24h by default.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

from ..config import settings

log = logging.getLogger("sentinelai.cache")


class _MemoryCache:
    backend = "in-memory"

    def __init__(self, max_items: int = 5_000) -> None:
        self._data: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self._max = max_items

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at and expires_at < time.time():
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any, ttl: int) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                # drop the soonest-to-expire quarter
                doomed = sorted(self._data.items(), key=lambda kv: kv[1][0])[: self._max // 4]
                for k, _ in doomed:
                    self._data.pop(k, None)
            self._data[key] = (time.time() + ttl if ttl else 0, value)

    def ttl(self, key: str) -> int:
        with self._lock:
            entry = self._data.get(key)
            if not entry or not entry[0]:
                return -1
            return max(int(entry[0] - time.time()), 0)

    def delete_prefix(self, prefix: str) -> int:
        with self._lock:
            keys = [k for k in self._data if k.startswith(prefix)]
            for k in keys:
                self._data.pop(k, None)
            return len(keys)

    def healthy(self) -> tuple[bool, str]:
        return True, "in-memory"


class _RedisCache:
    backend = "redis"

    def __init__(self, url: str) -> None:
        import redis  # imported lazily so the dependency stays optional

        self._client = redis.from_url(url, decode_responses=True, socket_timeout=3)
        self._client.ping()

    def get(self, key: str) -> Any | None:
        raw = self._client.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def set(self, key: str, value: Any, ttl: int) -> None:
        payload = json.dumps(value, default=str)
        if ttl:
            self._client.setex(key, ttl, payload)
        else:
            self._client.set(key, payload)

    def ttl(self, key: str) -> int:
        return int(self._client.ttl(key))

    def delete_prefix(self, prefix: str) -> int:
        removed = 0
        for key in self._client.scan_iter(match=f"{prefix}*", count=500):
            self._client.delete(key)
            removed += 1
        return removed

    def healthy(self) -> tuple[bool, str]:
        try:
            self._client.ping()
            return True, "redis"
        except Exception as exc:  # pragma: no cover - network dependent
            return False, str(exc)


def _build():
    if settings.redis_url:
        try:
            cache = _RedisCache(settings.redis_url)
            log.info("Cache backend: redis")
            return cache
        except Exception as exc:
            log.warning("Redis unreachable (%s) — using in-memory cache", exc)
    return _MemoryCache()


cache = _build()


def cache_backend() -> str:
    return cache.backend


def cache_status() -> dict:
    ok, detail = cache.healthy()
    return {"backend": cache.backend, "ok": ok, "detail": detail,
            "configured": bool(settings.redis_url)}
