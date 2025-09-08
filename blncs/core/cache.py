"""
BLNCS Caching Module
Simple in-memory caching for performance optimization.
"""

import time
import logging
from typing import Dict, Any, Optional, Callable
from threading import RLock


class SimpleCache:
    """Simple thread-safe in-memory cache with TTL"""
    
    def __init__(self, default_ttl: int = 300):
        self.default_ttl = default_ttl
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.lock = RLock()
        self.logger = logging.getLogger(__name__)
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                if time.time() < entry['expires_at']:
                    self.logger.debug(f"Cache hit for key: {key}")
                    return entry['value']
                else:
                    # Expired, remove from cache
                    del self.cache[key]
                    self.logger.debug(f"Cache miss (expired) for key: {key}")
            else:
                self.logger.debug(f"Cache miss for key: {key}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set cached value with TTL"""
        ttl = ttl or self.default_ttl
        expires_at = time.time() + ttl
        
        with self.lock:
            self.cache[key] = {
                'value': value,
                'expires_at': expires_at,
                'created_at': time.time()
            }
            self.logger.debug(f"Cached key: {key} (TTL: {ttl}s)")
    
    def delete(self, key: str) -> bool:
        """Delete cached value"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                self.logger.debug(f"Deleted cached key: {key}")
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cached values"""
        with self.lock:
            count = len(self.cache)
            self.cache.clear()
            self.logger.debug(f"Cleared {count} cached entries")
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed"""
        current_time = time.time()
        expired_keys = []
        
        with self.lock:
            for key, entry in self.cache.items():
                if current_time >= entry['expires_at']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.cache[key]
        
        if expired_keys:
            self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
        
        return len(expired_keys)
    
    def optimize_memory(self):
        """メモリ使用量を最適化"""
        with self.lock:
            # 期限切れエントリを削除
            self.cleanup_expired()
            
            # キャッシュサイズが大きすぎる場合は古いエントリを削除
            max_entries = 100  # 最大エントリ数
            if len(self.cache) > max_entries:
                # 作成時刻でソートして古いものから削除
                sorted_entries = sorted(
                    self.cache.items(),
                    key=lambda x: x[1]['created_at']
                )
                
                entries_to_remove = len(self.cache) - max_entries
                for i in range(entries_to_remove):
                    key = sorted_entries[i][0]
                    del self.cache[key]
                
                self.logger.debug(f"Removed {entries_to_remove} old cache entries for memory optimization")
    
    def get_or_set(self, key: str, factory: Callable[[], Any], ttl: Optional[int] = None) -> Any:
        """Get cached value or set it using factory function"""
        value = self.get(key)
        if value is not None:
            return value
        
        # Not in cache, generate and cache
        value = factory()
        self.set(key, value, ttl)
        return value
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            current_time = time.time()
            total_entries = len(self.cache)
            expired_entries = sum(1 for entry in self.cache.values() 
                                if current_time >= entry['expires_at'])
            active_entries = total_entries - expired_entries
            
            return {
                'total_entries': total_entries,
                'active_entries': active_entries,
                'expired_entries': expired_entries,
                'hit_ratio': getattr(self, '_hit_count', 0) / max(getattr(self, '_total_requests', 1), 1)
            }


# Global cache instance
_global_cache = SimpleCache()

def get_cache() -> SimpleCache:
    """Get the global cache instance"""
    return _global_cache

def cached(key_prefix: str = "", ttl: int = 300):
    """Decorator for caching function results"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{key_prefix}:{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            cache = get_cache()
            return cache.get_or_set(
                cache_key,
                lambda: func(*args, **kwargs),
                ttl
            )
        return wrapper
    return decorator