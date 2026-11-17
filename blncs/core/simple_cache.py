#!/usr/bin/env python3
"""
Simple Cache System for BLNCS
シンプルなキャッシュシステム
"""

import base64
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from datetime import date, datetime
from decimal import Decimal
from threading import Lock
from typing import Any, Callable, Dict, Optional, Union

# Try to import Redis for distributed caching
try:
    import redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

logger = logging.getLogger(__name__)

# Values stored in the Redis backend are serialized as JSON, never with
# pickle: a pickle payload is executable code for whoever can write to
# Redis, while JSON is inert data. JSON natively covers the values this
# cache actually carries (dicts, lists, strings, numbers, booleans,
# None). A small set of additional Python types is supported through
# explicit type tags below: tuple, set/frozenset, datetime, date,
# Decimal and bytes. Anything else (arbitrary objects) raises TypeError
# at write time and the entry is simply not cached.
_CACHE_TYPE_TAG = "__blncs_type__"


def _encode_cache_value(value: Any) -> Any:
    """Convert a cache value into a JSON-representable structure."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [_encode_cache_value(item) for item in value]
    if isinstance(value, tuple):
        return {
            _CACHE_TYPE_TAG: "tuple",
            "items": [_encode_cache_value(item) for item in value],
        }
    if isinstance(value, (set, frozenset)):
        return {
            _CACHE_TYPE_TAG: "set",
            "items": [_encode_cache_value(item) for item in value],
        }
    if isinstance(value, dict):
        if _CACHE_TYPE_TAG in value:
            # A user dict that itself contains the reserved tag key is
            # stored as key/value pairs so it round-trips unambiguously.
            return {
                _CACHE_TYPE_TAG: "dict",
                "pairs": [
                    [_encode_cache_value(k), _encode_cache_value(v)]
                    for k, v in value.items()
                ],
            }
        return {str(key): _encode_cache_value(item) for key, item in value.items()}
    if isinstance(value, datetime):
        return {_CACHE_TYPE_TAG: "datetime", "value": value.isoformat()}
    if isinstance(value, date):
        return {_CACHE_TYPE_TAG: "date", "value": value.isoformat()}
    if isinstance(value, Decimal):
        return {_CACHE_TYPE_TAG: "decimal", "value": str(value)}
    if isinstance(value, (bytes, bytearray)):
        return {
            _CACHE_TYPE_TAG: "bytes",
            "value": base64.b64encode(bytes(value)).decode("ascii"),
        }
    raise TypeError(
        f"Value of type {type(value).__name__} cannot be stored in the "
        "Redis cache backend (JSON-serializable values only)"
    )


def _decode_cache_value(node: Any) -> Any:
    """Rebuild a cache value from its JSON representation."""
    if isinstance(node, list):
        return [_decode_cache_value(item) for item in node]
    if isinstance(node, dict):
        tag = node.get(_CACHE_TYPE_TAG)
        if tag is None:
            return {key: _decode_cache_value(item) for key, item in node.items()}
        if tag == "tuple":
            return tuple(_decode_cache_value(item) for item in node["items"])
        if tag == "set":
            return {_decode_cache_value(item) for item in node["items"]}
        if tag == "dict":
            return {
                _decode_cache_value(k): _decode_cache_value(v) for k, v in node["pairs"]
            }
        if tag == "datetime":
            return datetime.fromisoformat(node["value"])
        if tag == "date":
            return date.fromisoformat(node["value"])
        if tag == "decimal":
            return Decimal(node["value"])
        if tag == "bytes":
            return base64.b64decode(node["value"].encode("ascii"))
        raise ValueError(f"Unknown cache value type tag: {tag!r}")
    return node


def _serialize_cache_value(value: Any) -> bytes:
    """Serialize a cache value to JSON bytes for the Redis backend."""
    return json.dumps(
        _encode_cache_value(value), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _deserialize_cache_value(raw: Any) -> Any:
    """Deserialize JSON bytes from the Redis backend back to a value.

    Raises ValueError/TypeError for anything that is not data written by
    _serialize_cache_value (including legacy pickle payloads); callers
    treat that as a cache miss instead of executing the payload.
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8")
    return _decode_cache_value(json.loads(raw))


class SimpleCache:
    """
    Simple in-memory cache with TTL support and optional Redis backend
    """

    def __init__(
        self,
        max_size: int = 1000,
        default_ttl: int = 3600,
        backend: str = "memory",
        redis_url: Optional[str] = None,
        ttl: Optional[int] = None,
    ):
        self.max_size = max_size
        # `ttl` is accepted as an alias for `default_ttl`.
        self.default_ttl = ttl if ttl is not None else default_ttl
        self.backend = backend
        self.redis_url = redis_url or os.getenv(
            "BLNCS_REDIS_URL", "redis://localhost:6379"
        )
        self._hits = 0
        self._misses = 0

        # Initialize backend
        if backend == "redis" and HAS_REDIS:
            self._init_redis()
        else:
            self._init_memory()

    def _init_memory(self):
        """Initialize in-memory cache"""
        self.cache = OrderedDict()
        self.expires = {}
        self.lock = Lock()
        self.backend = "memory"
        logger.info("Initialized in-memory cache")

    def _init_redis(self):
        """Initialize Redis cache"""
        try:
            self.redis_client = redis.from_url(self.redis_url)
            self.redis_client.ping()
            self.backend = "redis"
            logger.info(f"Initialized Redis cache at {self.redis_url}")
        except Exception as e:
            logger.warning(
                f"Failed to connect to Redis: {e}, falling back to memory cache"
            )
            self._init_memory()

    def _make_key(self, key: Union[str, tuple]) -> str:
        """Convert key to string format"""
        if isinstance(key, str):
            return key
        # For complex keys, create a hash. MD5 is only a cache-key
        # derivation here, not a security mechanism.
        key_str = json.dumps(key, sort_keys=True)
        return hashlib.md5(key_str.encode(), usedforsecurity=False).hexdigest()

    def get(self, key: Union[str, tuple], default: Any = None) -> Any:
        """Get value from cache"""
        key_str = self._make_key(key)

        if self.backend == "redis":
            return self._get_redis(key_str, default)
        else:
            return self._get_memory(key_str, default)

    def _get_memory(self, key: str, default: Any) -> Any:
        """Get from memory cache"""
        with self.lock:
            # Check if key exists and not expired
            if key in self.cache:
                if key in self.expires:
                    if time.time() > self.expires[key]:
                        # Expired, remove it
                        del self.cache[key]
                        del self.expires[key]
                        self._misses += 1
                        return default

                # Move to end (LRU)
                self.cache.move_to_end(key)
                self._hits += 1
                return self.cache[key]

            self._misses += 1
            return default

    def _get_redis(self, key: str, default: Any) -> Any:
        """Get from Redis cache"""
        try:
            value = self.redis_client.get(f"blncs:{key}")
            if value:
                decoded = _deserialize_cache_value(value)
                self._hits += 1
                return decoded
            self._misses += 1
            return default
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            self._misses += 1
            return default

    def set(
        self, key: Union[str, tuple], value: Any, ttl: Optional[int] = None
    ) -> bool:
        """Set value in cache"""
        key_str = self._make_key(key)
        ttl = ttl or self.default_ttl

        if self.backend == "redis":
            return self._set_redis(key_str, value, ttl)
        else:
            return self._set_memory(key_str, value, ttl)

    def _set_memory(self, key: str, value: Any, ttl: int) -> bool:
        """Set in memory cache"""
        with self.lock:
            # Remove oldest if at capacity
            if key not in self.cache and len(self.cache) >= self.max_size:
                # Remove oldest item
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                if oldest_key in self.expires:
                    del self.expires[oldest_key]

            # Set new value
            self.cache[key] = value
            if ttl > 0:
                self.expires[key] = time.time() + ttl

            return True

    def _set_redis(self, key: str, value: Any, ttl: int) -> bool:
        """Set in Redis cache"""
        try:
            serialized = _serialize_cache_value(value)
            if ttl > 0:
                self.redis_client.setex(f"blncs:{key}", ttl, serialized)
            else:
                self.redis_client.set(f"blncs:{key}", serialized)
            return True
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False

    def delete(self, key: Union[str, tuple]) -> bool:
        """Delete value from cache"""
        key_str = self._make_key(key)

        if self.backend == "redis":
            return self._delete_redis(key_str)
        else:
            return self._delete_memory(key_str)

    def _delete_memory(self, key: str) -> bool:
        """Delete from memory cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                if key in self.expires:
                    del self.expires[key]
                return True
            return False

    def _delete_redis(self, key: str) -> bool:
        """Delete from Redis cache"""
        try:
            return bool(self.redis_client.delete(f"blncs:{key}"))
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False

    def clear(self) -> bool:
        """Clear all cache entries"""
        if self.backend == "redis":
            return self._clear_redis()
        else:
            return self._clear_memory()

    def _clear_memory(self) -> bool:
        """Clear memory cache"""
        with self.lock:
            self.cache.clear()
            self.expires.clear()
            return True

    def _clear_redis(self) -> bool:
        """Clear Redis cache"""
        try:
            # Delete all keys with our prefix
            keys = self.redis_client.keys("blncs:*")
            if keys:
                self.redis_client.delete(*keys)
            return True
        except Exception as e:
            logger.error(f"Redis clear error: {e}")
            return False

    def size(self) -> int:
        """Get number of items in cache"""
        if self.backend == "redis":
            try:
                return len(self.redis_client.keys("blncs:*"))
            except:
                return 0
        else:
            with self.lock:
                return len(self.cache)

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics (size, hit/miss counters, limits)"""
        total_requests = self._hits + self._misses
        return {
            "size": self.size(),
            "hits": self._hits,
            "misses": self._misses,
            "total_requests": total_requests,
            "hit_rate": (self._hits / total_requests) if total_requests else 0.0,
            "max_size": self.max_size,
            "ttl": self.default_ttl,
            "backend": self.backend,
        }

    def configure(
        self,
        max_size: Optional[int] = None,
        default_ttl: Optional[int] = None,
        ttl: Optional[int] = None,
    ) -> None:
        """Update cache limits at runtime.

        Lowering ``max_size`` below the current number of entries evicts
        the least recently used entries until the cache fits again.
        """
        if ttl is not None:
            default_ttl = ttl
        if default_ttl is not None:
            self.default_ttl = default_ttl
        if max_size is not None:
            self.max_size = max_size
            if self.backend == "memory":
                with self.lock:
                    while len(self.cache) > self.max_size:
                        oldest_key, _ = self.cache.popitem(last=False)
                        self.expires.pop(oldest_key, None)

    def cache_decorator(self, ttl: Optional[int] = None):
        """Decorator for caching function results"""

        def decorator(func: Callable):
            def wrapper(*args, **kwargs):
                # Create cache key from function name and arguments
                cache_key = (func.__name__, args, tuple(sorted(kwargs.items())))

                # Try to get from cache
                result = self.get(cache_key)
                if result is not None:
                    return result

                # Call function and cache result
                result = func(*args, **kwargs)
                self.set(cache_key, result, ttl)
                return result

            return wrapper

        return decorator


class CacheManager:
    """Manager for multiple cache instances"""

    def __init__(self):
        self.caches: Dict[str, SimpleCache] = {}
        self.default_cache = SimpleCache()

    def get_cache(self, name: str = "default") -> SimpleCache:
        """Get or create named cache"""
        if name == "default":
            return self.default_cache

        if name not in self.caches:
            self.caches[name] = SimpleCache()

        return self.caches[name]

    def create_cache(
        self,
        name: str,
        max_size: int = 1000,
        default_ttl: int = 3600,
        backend: str = "memory",
        redis_url: Optional[str] = None,
    ) -> SimpleCache:
        """Create a new named cache"""
        cache = SimpleCache(
            max_size=max_size,
            default_ttl=default_ttl,
            backend=backend,
            redis_url=redis_url,
        )
        self.caches[name] = cache
        return cache

    def clear_all(self):
        """Clear all caches"""
        self.default_cache.clear()
        for cache in self.caches.values():
            cache.clear()


# Global cache manager instance
_cache_manager = CacheManager()


def get_simple_cache(name: str = "default") -> SimpleCache:
    """Get a cache instance by name"""
    return _cache_manager.get_cache(name)


def create_cache(
    name: str,
    max_size: int = 1000,
    default_ttl: int = 3600,
    backend: str = "memory",
    redis_url: Optional[str] = None,
) -> SimpleCache:
    """Create a new named cache"""
    return _cache_manager.create_cache(name, max_size, default_ttl, backend, redis_url)


def clear_all_caches():
    """Clear all caches"""
    _cache_manager.clear_all()


# Lightning-specific cache utilities
class LightningCache:
    """Cache utilities for Lightning Network operations"""

    def __init__(self, cache: Optional[SimpleCache] = None):
        self.cache = cache or get_simple_cache("lightning")

    def cache_channel_info(self, channel_id: str, info: dict, ttl: int = 300):
        """Cache channel information"""
        return self.cache.set(f"channel:{channel_id}", info, ttl)

    def get_channel_info(self, channel_id: str) -> Optional[dict]:
        """Get cached channel information"""
        return self.cache.get(f"channel:{channel_id}")

    def cache_route(self, payment_hash: str, route: list, ttl: int = 600):
        """Cache payment route"""
        return self.cache.set(f"route:{payment_hash}", route, ttl)

    def get_route(self, payment_hash: str) -> Optional[list]:
        """Get cached route"""
        return self.cache.get(f"route:{payment_hash}")

    def cache_node_info(self, node_id: str, info: dict, ttl: int = 3600):
        """Cache node information"""
        return self.cache.set(f"node:{node_id}", info, ttl)

    def get_node_info(self, node_id: str) -> Optional[dict]:
        """Get cached node information"""
        return self.cache.get(f"node:{node_id}")


__all__ = [
    "SimpleCache",
    "CacheManager",
    "LightningCache",
    "get_simple_cache",
    "create_cache",
    "clear_all_caches",
]
