"""
Fast, lightweight caching system for BLNCS
Optimized for speed with minimal overhead.
"""

import time
from typing import Any, Optional, Dict, Callable, TypeVar
from functools import wraps
import threading

T = TypeVar('T')


class FastCache:
    """Ultra-lightweight cache with minimal overhead"""
    
    def __init__(self, max_size: int = 1024, default_ttl: int = 600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, tuple] = {}  # key: (value, expire_time)
        self._access_order: list = []
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache"""
        current_time = time.time()
        
        with self._lock:
            if key in self._cache:
                value, expire_time = self._cache[key]
                if current_time < expire_time:
                    # Move to end (mark as recently used)
                    if key in self._access_order:
                        self._access_order.remove(key)
                    self._access_order.append(key)
                    self._hits += 1
                    return value
                else:
                    # Expired
                    del self._cache[key]
                    if key in self._access_order:
                        self._access_order.remove(key)
        
        self._misses += 1
        return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache"""
        expire_time = time.time() + (ttl or self.default_ttl)
        
        with self._lock:
            # Remove oldest items if cache is full
            while len(self._cache) >= self.max_size and key not in self._cache:
                if self._access_order:
                    oldest = self._access_order.pop(0)
                    self._cache.pop(oldest, None)
                else:
                    break
            
            self._cache[key] = (value, expire_time)
            
            # Update access order
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._hits = 0
            self._misses = 0
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count"""
        current_time = time.time()
        expired_count = 0
        
        with self._lock:
            expired_keys = []
            for key, (_, expire_time) in self._cache.items():
                if current_time >= expire_time:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                expired_count += 1
        
        return expired_count
    
    def stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0
            
            return {
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': hit_rate,
                'size': len(self._cache),
                'max_size': self.max_size
            }


class FastMemoize:
    """Ultra-fast function memoization decorator"""
    
    def __init__(self, ttl: int = 300, max_size: int = 128):
        self.cache = FastCache(max_size, ttl)
        self.ttl = ttl
    
    def __call__(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            # Try to get from cache
            result = self.cache.get(cache_key)
            if result is not None:
                return result
            
            # Calculate and cache result
            result = func(*args, **kwargs)
            self.cache.set(cache_key, result, self.ttl)
            return result
        
        # Add cache management methods to wrapper
        wrapper.cache_clear = self.cache.clear
        wrapper.cache_stats = self.cache.stats
        wrapper.cache_cleanup = self.cache.cleanup_expired
        
        return wrapper


# Global fast cache instance
_global_cache = None

def get_fast_cache() -> FastCache:
    """Get global fast cache instance"""
    global _global_cache
    if _global_cache is None:
        _global_cache = FastCache(max_size=512, default_ttl=300)
    return _global_cache


def fast_cache(ttl: int = 300, max_size: int = 128):
    """Decorator for fast function caching"""
    return FastMemoize(ttl=ttl, max_size=max_size)


def fast_cache_key(*args, **kwargs) -> str:
    """Generate fast cache key from arguments"""
    return f"{hash((args, tuple(sorted(kwargs.items()))))}"


class LazyLoader:
    """Lazy loading utility for modules and expensive operations"""
    
    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()
    
    def load_once(self, key: str, loader_func: Callable) -> Any:
        """Load expensive resource only once"""
        if key in self._cache:
            return self._cache[key]
        
        with self._lock:
            # Double-check pattern
            if key in self._cache:
                return self._cache[key]
            
            result = loader_func()
            self._cache[key] = result
            return result
    
    def invalidate(self, key: str) -> None:
        """Invalidate cached resource"""
        with self._lock:
            self._cache.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cached resources"""
        with self._lock:
            self._cache.clear()


# Global lazy loader
_lazy_loader = LazyLoader()

def lazy_load(key: str, loader_func: Callable) -> Any:
    """Lazy load expensive resource"""
    return _lazy_loader.load_once(key, loader_func)


def invalidate_lazy(key: str) -> None:
    """Invalidate lazy-loaded resource"""
    _lazy_loader.invalidate(key)


# Backward compatibility aliases for old cache.py
def get_cache() -> FastCache:
    """Get cache instance (backward compatibility)"""
    return get_fast_cache()

def get_cache_manager() -> FastCache:
    """Get cache manager (backward compatibility alias)"""
    return get_fast_cache()

def cached(ttl: int = 300):
    """Cached decorator (backward compatibility)"""
    return fast_cache(ttl=ttl)

class SimpleCache:
    """Backward compatibility class for old SimpleCache"""
    def __init__(self, default_ttl: int = 300):
        self._cache = get_fast_cache()
        self.default_ttl = default_ttl
    
    def get(self, key: str):
        return self._cache.get(key)
    
    def set(self, key: str, value, ttl=None):
        return self._cache.set(key, value, ttl or self.default_ttl)
    
    def delete(self, key: str):
        return self._cache.delete(key)
    
    def clear(self):
        return self._cache.clear()
    
    def cleanup_expired(self):
        return self._cache.cleanup()
    
    def optimize_memory(self):
        return self._cache.cleanup()
    
    def get_or_set(self, key: str, factory, ttl=None):
        value = self.get(key)
        if value is not None:
            return value
        value = factory()
        self.set(key, value, ttl)
        return value
    
    def stats(self):
        return self._cache.stats()