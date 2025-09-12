"""
Simple Cache System for BLNCS
Lightweight caching with TTL and LRU eviction.
"""

import time
import threading
from typing import Any, Optional, Dict, Callable
from collections import OrderedDict
from dataclasses import dataclass

@dataclass
class CacheEntry:
    """Simple cache entry"""
    value: Any
    expires_at: float
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        return self.expires_at > 0 and time.time() > self.expires_at

class SimpleCache:
    """Simple LRU cache with TTL support"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache"""
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if entry.is_expired():
                    del self._cache[key]
                    return default
                
                # Move to end (most recently used)
                self._cache.move_to_end(key)
                return entry.value
            return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache"""
        with self._lock:
            if ttl is None:
                ttl = self.default_ttl
            
            expires_at = time.time() + ttl if ttl > 0 else 0
            self._cache[key] = CacheEntry(value, expires_at)
            self._cache.move_to_end(key)
            
            # Evict oldest entries if over size limit
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove expired entries, return count removed"""
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]
            
            for key in expired_keys:
                del self._cache[key]
            
            return len(expired_keys)
    
    def size(self) -> int:
        """Get current cache size"""
        return len(self._cache)
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'utilization': len(self._cache) / self.max_size if self.max_size > 0 else 0,
                'default_ttl': self.default_ttl
            }

def cached(ttl: int = 300, cache_instance: Optional[SimpleCache] = None):
    """Decorator for caching function results"""
    def decorator(func: Callable) -> Callable:
        cache = cache_instance or get_cache()
        
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            key_parts = [func.__name__]
            if args:
                key_parts.append(str(hash(args)))
            if kwargs:
                key_parts.append(str(hash(tuple(sorted(kwargs.items())))))
            cache_key = ':'.join(key_parts)
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Compute and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        
        wrapper.__wrapped__ = func  # Store original function
        return wrapper
    
    return decorator

# Global cache instances
_default_cache = None
_cache_lock = threading.Lock()

def get_cache() -> SimpleCache:
    """Get default cache instance"""
    global _default_cache
    if _default_cache is None:
        with _cache_lock:
            if _default_cache is None:
                _default_cache = SimpleCache()
    return _default_cache

def get_typed_cache(cache_type: str = 'default') -> SimpleCache:
    """Get typed cache instance (for compatibility)"""
    # For simplicity, return the same cache instance
    return get_cache()

# Cleanup thread to remove expired entries
_cleanup_thread = None

def start_cleanup_thread():
    """Start background cleanup thread"""
    global _cleanup_thread
    if _cleanup_thread is None or not _cleanup_thread.is_alive():
        def cleanup_worker():
            while True:
                try:
                    cache = get_cache()
                    removed = cache.cleanup_expired()
                    if removed > 0:
                        print(f"Cache cleanup: removed {removed} expired entries")
                    time.sleep(60)  # Cleanup every minute
                except Exception as e:
                    print(f"Cache cleanup error: {e}")
                    time.sleep(60)
        
        _cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        _cleanup_thread.start()

# Auto-start cleanup thread
start_cleanup_thread()

__all__ = ['SimpleCache', 'cached', 'get_cache', 'get_typed_cache', 'CacheEntry']