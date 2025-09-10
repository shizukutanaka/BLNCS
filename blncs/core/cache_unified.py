"""
Unified Caching System for BLNCS
High-performance, memory-efficient caching with multiple strategies.
"""

import time
import threading
import hashlib
import json
import pickle
from typing import Dict, Any, Optional, Callable, Union, TypeVar, List
from functools import wraps
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from enum import Enum

from .logger import get_logger

logger = get_logger(__name__)

T = TypeVar('T')

class CacheStrategy(Enum):
    """Cache eviction strategies."""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In First Out
    TTL = "ttl"  # Time To Live based

@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    size: int
    ttl: float
    created_at: float
    last_accessed: float
    access_count: int = 0
    
    def is_expired(self) -> bool:
        """Check if entry is expired."""
        if self.ttl <= 0:
            return False
        return time.time() > self.created_at + self.ttl

class UnifiedCache:
    """Unified high-performance cache with multiple strategies."""
    
    def __init__(self, max_size: int = 10000, max_memory_mb: int = 100, 
                 default_ttl: int = 300, strategy: CacheStrategy = CacheStrategy.LRU):
        """Initialize unified cache."""
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.default_ttl = default_ttl
        self.strategy = strategy
        
        # Storage
        self._cache: Dict[str, CacheEntry] = {}
        self._order: OrderedDict = OrderedDict()  # For LRU/FIFO
        self._frequency: defaultdict = defaultdict(int)  # For LFU
        
        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._current_memory = 0
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Cleanup thread
        self._cleanup_interval = 60  # seconds
        self._last_cleanup = time.time()
        
        self.logger = get_logger(__name__)
    
    def _estimate_size(self, value: Any) -> int:
        """Estimate memory size of value in bytes."""
        try:
            if isinstance(value, (str, bytes)):
                return len(value)
            elif isinstance(value, (int, float, bool)):
                return 8
            elif isinstance(value, (list, tuple)):
                return sum(self._estimate_size(item) for item in value) + 24
            elif isinstance(value, dict):
                size = 24
                for k, v in value.items():
                    size += self._estimate_size(k) + self._estimate_size(v)
                return size
            else:
                # Fallback to pickle size estimation
                return len(pickle.dumps(value))
        except:
            return 100  # Default size if estimation fails
    
    def _evict_lru(self):
        """Evict least recently used entry."""
        if self._order:
            oldest_key = next(iter(self._order))
            self._remove_entry(oldest_key)
    
    def _evict_lfu(self):
        """Evict least frequently used entry."""
        if self._cache:
            min_freq = min(self._frequency.values())
            for key in list(self._cache.keys()):
                if self._frequency[key] == min_freq:
                    self._remove_entry(key)
                    break
    
    def _evict_fifo(self):
        """Evict first in first out."""
        if self._cache:
            oldest_entry = min(self._cache.values(), key=lambda e: e.created_at)
            self._remove_entry(oldest_entry.key)
    
    def _evict_ttl(self):
        """Evict expired entries first, then oldest."""
        # First try to evict expired entries
        for key, entry in list(self._cache.items()):
            if entry.is_expired():
                self._remove_entry(key)
                return
        
        # If no expired entries, evict oldest
        if self._cache:
            oldest_entry = min(self._cache.values(), key=lambda e: e.created_at)
            self._remove_entry(oldest_entry.key)
    
    def _evict(self):
        """Evict entry based on strategy."""
        if self.strategy == CacheStrategy.LRU:
            self._evict_lru()
        elif self.strategy == CacheStrategy.LFU:
            self._evict_lfu()
        elif self.strategy == CacheStrategy.FIFO:
            self._evict_fifo()
        elif self.strategy == CacheStrategy.TTL:
            self._evict_ttl()
        
        self._evictions += 1
    
    def _remove_entry(self, key: str):
        """Remove entry from cache."""
        if key in self._cache:
            entry = self._cache[key]
            self._current_memory -= entry.size
            del self._cache[key]
            
            if key in self._order:
                del self._order[key]
            if key in self._frequency:
                del self._frequency[key]
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        current_time = time.time()
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        expired_keys = [
            key for key, entry in self._cache.items()
            if entry.is_expired()
        ]
        
        for key in expired_keys:
            self._remove_entry(key)
        
        self._last_cleanup = current_time
        
        if expired_keys:
            self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        with self._lock:
            # Periodic cleanup
            self._cleanup_expired()
            
            if key not in self._cache:
                self._misses += 1
                return default
            
            entry = self._cache[key]
            
            # Check expiration
            if entry.is_expired():
                self._remove_entry(key)
                self._misses += 1
                return default
            
            # Update access metadata
            entry.last_accessed = time.time()
            entry.access_count += 1
            
            # Update order for LRU
            if self.strategy == CacheStrategy.LRU and key in self._order:
                self._order.move_to_end(key)
            
            # Update frequency for LFU
            if self.strategy == CacheStrategy.LFU:
                self._frequency[key] += 1
            
            self._hits += 1
            return entry.value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache."""
        with self._lock:
            # Estimate size
            size = self._estimate_size(value)
            
            # Check memory limit
            while self._current_memory + size > self.max_memory_bytes and self._cache:
                self._evict()
            
            # Check size limit
            while len(self._cache) >= self.max_size:
                self._evict()
            
            # Remove old entry if exists
            if key in self._cache:
                self._remove_entry(key)
            
            # Create new entry
            current_time = time.time()
            entry = CacheEntry(
                key=key,
                value=value,
                size=size,
                ttl=ttl if ttl is not None else self.default_ttl,
                created_at=current_time,
                last_accessed=current_time,
                access_count=0
            )
            
            # Store entry
            self._cache[key] = entry
            self._current_memory += size
            
            # Update order for LRU/FIFO
            if self.strategy in [CacheStrategy.LRU, CacheStrategy.FIFO]:
                self._order[key] = current_time
            
            # Initialize frequency for LFU
            if self.strategy == CacheStrategy.LFU:
                self._frequency[key] = 1
            
            return True
    
    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        with self._lock:
            if key in self._cache:
                self._remove_entry(key)
                return True
            return False
    
    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._order.clear()
            self._frequency.clear()
            self._current_memory = 0
            self.logger.info("Cache cleared")
    
    def exists(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        with self._lock:
            if key not in self._cache:
                return False
            
            entry = self._cache[key]
            if entry.is_expired():
                self._remove_entry(key)
                return False
            
            return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                "entries": len(self._cache),
                "memory_mb": self._current_memory / (1024 * 1024),
                "memory_limit_mb": self.max_memory_bytes / (1024 * 1024),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate,
                "evictions": self._evictions,
                "strategy": self.strategy.value
            }
    
    def get_keys(self, pattern: Optional[str] = None) -> List[str]:
        """Get cache keys with optional pattern matching."""
        with self._lock:
            if pattern:
                import fnmatch
                return [k for k in self._cache.keys() if fnmatch.fnmatch(k, pattern)]
            return list(self._cache.keys())

# Specialized caches for different data types
class TypedCache:
    """Type-specific cache manager."""
    
    def __init__(self):
        """Initialize typed cache manager."""
        self.caches = {
            "lightning": UnifiedCache(max_size=1000, default_ttl=300, strategy=CacheStrategy.LRU),
            "config": UnifiedCache(max_size=100, default_ttl=900, strategy=CacheStrategy.TTL),
            "api": UnifiedCache(max_size=500, default_ttl=60, strategy=CacheStrategy.LRU),
            "metrics": UnifiedCache(max_size=2000, default_ttl=30, strategy=CacheStrategy.FIFO),
            "general": UnifiedCache(max_size=5000, default_ttl=600, strategy=CacheStrategy.LRU)
        }
    
    def get_cache(self, cache_type: str = "general") -> UnifiedCache:
        """Get specific cache instance."""
        return self.caches.get(cache_type, self.caches["general"])
    
    def get(self, key: str, cache_type: str = "general", default: Any = None) -> Any:
        """Get from typed cache."""
        return self.get_cache(cache_type).get(key, default)
    
    def set(self, key: str, value: Any, cache_type: str = "general", ttl: Optional[int] = None) -> bool:
        """Set in typed cache."""
        return self.get_cache(cache_type).set(key, value, ttl)
    
    def clear_all(self):
        """Clear all caches."""
        for cache in self.caches.values():
            cache.clear()
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all caches."""
        return {name: cache.get_stats() for name, cache in self.caches.items()}

# Cache decorators
def cached(ttl: int = 300, cache_type: str = "general", key_func: Optional[Callable] = None):
    """Decorator for caching function results."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation
                key_parts = [func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = ":".join(key_parts)
            
            # Get from cache
            cache = get_typed_cache()
            result = cache.get(cache_key, cache_type)
            
            if result is not None:
                return result
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Store in cache
            cache.set(cache_key, result, cache_type, ttl)
            
            return result
        
        wrapper.cache_clear = lambda: get_typed_cache().get_cache(cache_type).clear()
        return wrapper
    return decorator

def memoize(maxsize: int = 128):
    """Simple memoization decorator."""
    def decorator(func: Callable) -> Callable:
        cache = {}
        order = []
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create key from arguments
            key = (args, tuple(sorted(kwargs.items())))
            
            if key in cache:
                return cache[key]
            
            # Compute result
            result = func(*args, **kwargs)
            
            # Store in cache
            cache[key] = result
            order.append(key)
            
            # Evict if needed
            if len(cache) > maxsize:
                old_key = order.pop(0)
                del cache[old_key]
            
            return result
        
        wrapper.cache_clear = lambda: cache.clear()
        return wrapper
    return decorator

# Global cache instances
_unified_cache: Optional[UnifiedCache] = None
_typed_cache: Optional[TypedCache] = None
_cache_lock = threading.Lock()

def get_cache() -> UnifiedCache:
    """Get global unified cache instance."""
    global _unified_cache
    if _unified_cache is None:
        with _cache_lock:
            if _unified_cache is None:
                _unified_cache = UnifiedCache()
    return _unified_cache

def get_typed_cache() -> TypedCache:
    """Get global typed cache instance."""
    global _typed_cache
    if _typed_cache is None:
        with _cache_lock:
            if _typed_cache is None:
                _typed_cache = TypedCache()
    return _typed_cache

# Backward compatibility
def get_cache_manager():
    """Backward compatibility for old cache manager."""
    return get_cache()

def get_fast_cache():
    """Backward compatibility for fast cache."""
    return get_cache()

FastCache = UnifiedCache  # Alias for backward compatibility

if __name__ == "__main__":
    # Test the cache
    cache = get_cache()
    
    # Test basic operations
    cache.set("test_key", {"data": "test_value"}, ttl=60)
    print(f"Get test_key: {cache.get('test_key')}")
    
    # Test typed cache
    typed = get_typed_cache()
    typed.set("lightning_data", {"channels": []}, "lightning")
    typed.set("api_response", {"status": "ok"}, "api", ttl=30)
    
    # Test cache decorator
    @cached(ttl=10, cache_type="api")
    def expensive_operation(x: int) -> int:
        time.sleep(1)  # Simulate expensive operation
        return x * 2
    
    # First call (slow)
    start = time.time()
    result1 = expensive_operation(5)
    print(f"First call: {result1}, Time: {time.time() - start:.2f}s")
    
    # Second call (fast, from cache)
    start = time.time()
    result2 = expensive_operation(5)
    print(f"Second call: {result2}, Time: {time.time() - start:.2f}s")
    
    # Get statistics
    print(f"Cache stats: {cache.get_stats()}")
    print(f"All cache stats: {typed.get_all_stats()}")