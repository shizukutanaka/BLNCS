#!/usr/bin/env python3
"""
Distributed Caching Module
Implements Redis-like and Memcached-like caching patterns
Based on 2025 research on distributed caching strategies
"""

import logging
import time
import hashlib
from typing import Dict, Any, Optional, List, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
import json

logger = logging.getLogger(__name__)


class CacheBackend(Enum):
    """Cache backend types"""
    MEMORY = "memory"
    REDIS = "redis"
    MEMCACHED = "memcached"


class EvictionPolicy(Enum):
    """Cache eviction policies"""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In First Out
    TTL = "ttl"  # Time To Live


@dataclass
class CacheEntry:
    """Individual cache entry"""
    key: str
    value: Any
    ttl_seconds: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 0
    size_bytes: int = 0

    def is_expired(self) -> bool:
        """Check if entry has expired"""
        if self.ttl_seconds is None:
            return False

        elapsed = (datetime.utcnow() - self.created_at).total_seconds()
        return elapsed > self.ttl_seconds

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'key': self.key,
            'ttl_seconds': self.ttl_seconds,
            'access_count': self.access_count,
            'size_bytes': self.size_bytes,
            'is_expired': self.is_expired()
        }


@dataclass
class CacheMetrics:
    """Cache performance metrics"""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    evictions: int = 0
    total_memory_bytes: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        if self.total_requests == 0:
            return 0.0
        return (self.cache_hits / self.total_requests) * 100

    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate"""
        return 100 - self.hit_rate

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_requests': self.total_requests,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'hit_rate': self.hit_rate,
            'miss_rate': self.miss_rate,
            'evictions': self.evictions,
            'total_memory_bytes': self.total_memory_bytes
        }


class CacheStore(ABC):
    """Abstract cache store interface"""

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Set value in cache"""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists"""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all entries"""
        pass

    @abstractmethod
    def get_metrics(self) -> CacheMetrics:
        """Get cache metrics"""
        pass


class InMemoryCache(CacheStore):
    """
    In-memory cache store with eviction policies
    Suitable for single-node caching
    """

    def __init__(
        self,
        max_size_bytes: int = 100 * 1024 * 1024,  # 100MB
        eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    ):
        """Initialize in-memory cache"""
        self.max_size_bytes = max_size_bytes
        self.eviction_policy = eviction_policy
        self.cache: Dict[str, CacheEntry] = {}
        self.metrics = CacheMetrics()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        self.metrics.total_requests += 1

        if key not in self.cache:
            self.metrics.cache_misses += 1
            return None

        entry = self.cache[key]

        # Check expiration
        if entry.is_expired():
            del self.cache[key]
            self.metrics.cache_misses += 1
            return None

        # Update access info
        entry.last_accessed = datetime.utcnow()
        entry.access_count += 1
        self.metrics.cache_hits += 1

        logger.debug(f"Cache hit: {key}")
        return entry.value

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Set value in cache"""
        # Calculate entry size
        try:
            value_json = json.dumps(value, default=str)
            size = len(value_json.encode())
        except (TypeError, ValueError):
            size = 1000  # Estimate for non-JSON objects

        entry = CacheEntry(
            key=key,
            value=value,
            ttl_seconds=ttl_seconds,
            size_bytes=size
        )

        # Evict if necessary
        while self._total_size() + size > self.max_size_bytes and self.cache:
            self._evict_entry()

        self.cache[key] = entry
        logger.debug(f"Cache set: {key} ({size} bytes)")

    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if key in self.cache:
            del self.cache[key]
            logger.debug(f"Cache delete: {key}")
            return True
        return False

    def exists(self, key: str) -> bool:
        """Check if key exists and not expired"""
        if key not in self.cache:
            return False

        entry = self.cache[key]
        if entry.is_expired():
            del self.cache[key]
            return False

        return True

    def clear(self) -> None:
        """Clear all entries"""
        self.cache.clear()
        self.metrics.evictions = 0
        logger.info("Cache cleared")

    def get_metrics(self) -> CacheMetrics:
        """Get cache metrics"""
        self.metrics.total_memory_bytes = self._total_size()
        return self.metrics

    def _total_size(self) -> int:
        """Calculate total cache size in bytes"""
        return sum(entry.size_bytes for entry in self.cache.values())

    def _evict_entry(self) -> None:
        """Evict entry based on policy"""
        if not self.cache:
            return

        if self.eviction_policy == EvictionPolicy.LRU:
            # Least recently used
            key = min(self.cache.keys(), key=lambda k: self.cache[k].last_accessed)

        elif self.eviction_policy == EvictionPolicy.LFU:
            # Least frequently used
            key = min(self.cache.keys(), key=lambda k: self.cache[k].access_count)

        elif self.eviction_policy == EvictionPolicy.FIFO:
            # First in first out
            key = min(self.cache.keys(), key=lambda k: self.cache[k].created_at)

        elif self.eviction_policy == EvictionPolicy.TTL:
            # Expire oldest TTL first
            key = min(self.cache.keys(), key=lambda k: self.cache[k].ttl_seconds or float('inf'))

        else:
            key = next(iter(self.cache))

        del self.cache[key]
        self.metrics.evictions += 1
        logger.debug(f"Evicted: {key} (policy: {self.eviction_policy.value})")


class DistributedCacheLayer:
    """
    Multi-level caching with fallback chain
    L1: Memory cache, L2: Distributed store
    """

    def __init__(self, l1_cache: Optional[CacheStore] = None):
        """Initialize multi-level cache"""
        self.l1_cache = l1_cache or InMemoryCache()
        self.l2_stores: Dict[str, CacheStore] = {}  # For backend integrations
        self.metrics = CacheMetrics()

    def get(self, key: str) -> Optional[Any]:
        """Get from L1 or L2"""
        # Try L1 first
        value = self.l1_cache.get(key)
        if value is not None:
            self.metrics.cache_hits += 1
            self.metrics.total_requests += 1
            return value

        # Try L2 stores (in order)
        for store in self.l2_stores.values():
            value = store.get(key)
            if value is not None:
                # Backfill to L1
                self.l1_cache.set(key, value)
                self.metrics.cache_hits += 1
                self.metrics.total_requests += 1
                return value

        self.metrics.cache_misses += 1
        self.metrics.total_requests += 1
        return None

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Set in all cache levels"""
        self.l1_cache.set(key, value, ttl_seconds)

        for store in self.l2_stores.values():
            store.set(key, value, ttl_seconds)

    def delete(self, key: str) -> None:
        """Delete from all levels"""
        self.l1_cache.delete(key)

        for store in self.l2_stores.values():
            store.delete(key)

    def add_l2_store(self, name: str, store: CacheStore) -> None:
        """Add L2 cache store"""
        self.l2_stores[name] = store
        logger.info(f"Added L2 cache store: {name}")

    def get_metrics(self) -> CacheMetrics:
        """Get aggregated metrics"""
        l1_metrics = self.l1_cache.get_metrics()
        self.metrics = CacheMetrics(
            total_requests=l1_metrics.total_requests,
            cache_hits=l1_metrics.cache_hits,
            cache_misses=l1_metrics.cache_misses,
            evictions=l1_metrics.evictions,
            total_memory_bytes=l1_metrics.total_memory_bytes
        )
        return self.metrics


class CacheWarmer:
    """Preload cache with frequently accessed data"""

    def __init__(self, cache: CacheStore):
        """Initialize cache warmer"""
        self.cache = cache
        self.warm_data: Dict[str, Any] = {}

    def register_warm_data(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Register data to preload"""
        self.warm_data[key] = (value, ttl)

    def warm_cache(self) -> None:
        """Preload all registered data"""
        for key, (value, ttl) in self.warm_data.items():
            self.cache.set(key, value, ttl)
            logger.info(f"Warmed cache: {key}")

    def warm_cache_async(self, loader: Callable) -> None:
        """Load data via callable"""
        data = loader()
        for key, value in data.items():
            self.cache.set(key, value)


class CacheInvalidator:
    """Intelligent cache invalidation strategies"""

    def __init__(self, cache: CacheStore):
        """Initialize invalidator"""
        self.cache = cache
        self.dependencies: Dict[str, Set[str]] = {}  # key -> dependent keys

    def register_dependency(self, key: str, dependent_key: str) -> None:
        """Register cache dependency"""
        if key not in self.dependencies:
            self.dependencies[key] = set()
        self.dependencies[key].add(dependent_key)

    def invalidate(self, key: str, recursive: bool = True) -> int:
        """
        Invalidate cache entry and dependents

        Returns:
            Number of entries invalidated
        """
        count = 0

        # Delete primary key
        if self.cache.delete(key):
            count += 1

        # Delete dependent keys
        if recursive and key in self.dependencies:
            for dependent in self.dependencies[key]:
                count += self.invalidate(dependent, recursive=True)

        logger.info(f"Invalidated {count} cache entries")
        return count

    def tag_based_invalidation(self, tag: str, pattern_keys: List[str]) -> int:
        """Invalidate all keys matching tag pattern"""
        count = 0
        for key in pattern_keys:
            if tag in key:
                if self.cache.delete(key):
                    count += 1

        return count


__all__ = [
    'CacheBackend',
    'EvictionPolicy',
    'CacheEntry',
    'CacheMetrics',
    'CacheStore',
    'InMemoryCache',
    'DistributedCacheLayer',
    'CacheWarmer',
    'CacheInvalidator',
]
