"""
Advanced Caching System
Multi-backend caching with automatic invalidation and warming
"""

import time
import json
import pickle
import hashlib
import threading
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict
import heapq


class CacheBackend(Enum):
    """Cache backend types"""
    MEMORY = "memory"
    REDIS = "redis"
    MEMCACHED = "memcached"
    FILE = "file"
    HYBRID = "hybrid"


class EvictionPolicy(Enum):
    """Cache eviction policies"""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In First Out
    TTL = "ttl"  # Time To Live
    RANDOM = "random"


@dataclass
class CacheEntry:
    """Cache entry"""
    key: str
    value: Any
    size: int
    created_at: float = field(default_factory=time.time)
    accessed_at: float = field(default_factory=time.time)
    access_count: int = 1
    ttl: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if self.ttl is None:
            return False
        return time.time() > self.created_at + self.ttl
        
    def update_access(self):
        """Update access statistics"""
        self.accessed_at = time.time()
        self.access_count += 1


class CacheStats:
    """Cache statistics"""
    
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.evictions = 0
        self.lock = threading.Lock()
        
    def record_hit(self):
        """Record cache hit"""
        with self.lock:
            self.hits += 1
            
    def record_miss(self):
        """Record cache miss"""
        with self.lock:
            self.misses += 1
            
    def record_set(self):
        """Record cache set"""
        with self.lock:
            self.sets += 1
            
    def record_delete(self):
        """Record cache delete"""
        with self.lock:
            self.deletes += 1
            
    def record_eviction(self):
        """Record cache eviction"""
        with self.lock:
            self.evictions += 1
            
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate,
                "sets": self.sets,
                "deletes": self.deletes,
                "evictions": self.evictions,
                "total_requests": total_requests
            }


class MemoryCache:
    """In-memory cache implementation"""
    
    def __init__(self, max_size: int = 10000, max_memory: int = 104857600,
                 eviction_policy: EvictionPolicy = EvictionPolicy.LRU):
        self.max_size = max_size
        self.max_memory = max_memory
        self.eviction_policy = eviction_policy
        self.cache = OrderedDict() if eviction_policy == EvictionPolicy.LRU else {}
        self.current_size = 0
        self.current_memory = 0
        self.stats = CacheStats()
        self.lock = threading.RLock()
        
        # For LFU policy
        if eviction_policy == EvictionPolicy.LFU:
            self.frequency_heap = []
            
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check expiration
                if entry.is_expired():
                    self._delete_internal(key)
                    self.stats.record_miss()
                    return None
                    
                # Update access
                entry.update_access()
                
                # Update order for LRU
                if self.eviction_policy == EvictionPolicy.LRU:
                    self.cache.move_to_end(key)
                    
                self.stats.record_hit()
                return entry.value
            else:
                self.stats.record_miss()
                return None
                
    def set(self, key: str, value: Any, ttl: Optional[int] = None, 
           tags: Optional[List[str]] = None):
        """Set value in cache"""
        with self.lock:
            # Calculate size
            size = self._calculate_size(value)
            
            # Check if we need to evict
            while (self.current_size >= self.max_size or 
                   self.current_memory + size > self.max_memory):
                if not self._evict():
                    break
                    
            # Create entry
            entry = CacheEntry(
                key=key,
                value=value,
                size=size,
                ttl=ttl,
                tags=tags or []
            )
            
            # Remove old entry if exists
            if key in self.cache:
                old_entry = self.cache[key]
                self.current_memory -= old_entry.size
                
            # Add new entry
            self.cache[key] = entry
            self.current_size = len(self.cache)
            self.current_memory += size
            
            # Update LFU heap
            if self.eviction_policy == EvictionPolicy.LFU:
                heapq.heappush(self.frequency_heap, (1, time.time(), key))
                
            self.stats.record_set()
            
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        with self.lock:
            return self._delete_internal(key)
            
    def _delete_internal(self, key: str) -> bool:
        """Internal delete method"""
        if key in self.cache:
            entry = self.cache[key]
            self.current_memory -= entry.size
            del self.cache[key]
            self.current_size = len(self.cache)
            self.stats.record_delete()
            return True
        return False
        
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.current_size = 0
            self.current_memory = 0
            if self.eviction_policy == EvictionPolicy.LFU:
                self.frequency_heap.clear()
                
    def _evict(self) -> bool:
        """Evict entry based on policy"""
        if not self.cache:
            return False
            
        key_to_evict = None
        
        if self.eviction_policy == EvictionPolicy.LRU:
            # Evict least recently used
            key_to_evict = next(iter(self.cache))
            
        elif self.eviction_policy == EvictionPolicy.LFU:
            # Evict least frequently used
            while self.frequency_heap:
                freq, timestamp, key = heapq.heappop(self.frequency_heap)
                if key in self.cache:
                    key_to_evict = key
                    break
                    
        elif self.eviction_policy == EvictionPolicy.FIFO:
            # Evict first in
            key_to_evict = next(iter(self.cache))
            
        elif self.eviction_policy == EvictionPolicy.TTL:
            # Evict expired or oldest
            for key, entry in self.cache.items():
                if entry.is_expired():
                    key_to_evict = key
                    break
            if not key_to_evict:
                key_to_evict = min(self.cache.keys(), 
                                 key=lambda k: self.cache[k].created_at)
                                 
        elif self.eviction_policy == EvictionPolicy.RANDOM:
            # Evict random entry
            import random
            key_to_evict = random.choice(list(self.cache.keys()))
            
        if key_to_evict:
            self._delete_internal(key_to_evict)
            self.stats.record_eviction()
            return True
            
        return False
        
    def _calculate_size(self, value: Any) -> int:
        """Calculate size of value"""
        try:
            return len(pickle.dumps(value))
        except Exception:
            return 1000  # Default size
            
    def get_by_tag(self, tag: str) -> List[Tuple[str, Any]]:
        """Get all entries with specific tag"""
        with self.lock:
            results = []
            for key, entry in self.cache.items():
                if tag in entry.tags and not entry.is_expired():
                    results.append((key, entry.value))
            return results
            
    def invalidate_by_tag(self, tag: str):
        """Invalidate all entries with specific tag"""
        with self.lock:
            keys_to_delete = []
            for key, entry in self.cache.items():
                if tag in entry.tags:
                    keys_to_delete.append(key)
                    
            for key in keys_to_delete:
                self._delete_internal(key)


class FileCache:
    """File-based cache implementation"""
    
    def __init__(self, cache_dir: str = "/tmp/blrcs_cache",
                 max_files: int = 1000):
        self.cache_dir = Path(cache_dir)
        self.max_files = max_files
        self.stats = CacheStats()
        self.lock = threading.Lock()
        
        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
    def _get_file_path(self, key: str) -> Path:
        """Get file path for cache key"""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"
        
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        file_path = self._get_file_path(key)
        
        with self.lock:
            if file_path.exists():
                try:
                    with open(file_path, 'rb') as f:
                        entry = pickle.load(f)
                        
                    # Check expiration
                    if entry.is_expired():
                        file_path.unlink()
                        self.stats.record_miss()
                        return None
                        
                    entry.update_access()
                    
                    # Update file with new access info
                    with open(file_path, 'wb') as f:
                        pickle.dump(entry, f)
                        
                    self.stats.record_hit()
                    return entry.value
                    
                except Exception:
                    self.stats.record_miss()
                    return None
            else:
                self.stats.record_miss()
                return None
                
    def set(self, key: str, value: Any, ttl: Optional[int] = None,
           tags: Optional[List[str]] = None):
        """Set value in cache"""
        file_path = self._get_file_path(key)
        
        with self.lock:
            # Check file limit
            cache_files = list(self.cache_dir.glob("*.cache"))
            if len(cache_files) >= self.max_files:
                # Remove oldest file
                oldest_file = min(cache_files, key=lambda f: f.stat().st_mtime)
                oldest_file.unlink()
                self.stats.record_eviction()
                
            # Create entry
            entry = CacheEntry(
                key=key,
                value=value,
                size=0,  # Not tracking size for file cache
                ttl=ttl,
                tags=tags or []
            )
            
            # Write to file
            try:
                with open(file_path, 'wb') as f:
                    pickle.dump(entry, f)
                self.stats.record_set()
            except Exception:
                pass
                
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        file_path = self._get_file_path(key)
        
        with self.lock:
            if file_path.exists():
                file_path.unlink()
                self.stats.record_delete()
                return True
            return False
            
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink()


class HybridCache:
    """Hybrid cache with multiple backends"""
    
    def __init__(self, primary_backend: CacheBackend = CacheBackend.MEMORY,
                 secondary_backend: Optional[CacheBackend] = CacheBackend.FILE):
        self.primary = self._create_backend(primary_backend)
        self.secondary = self._create_backend(secondary_backend) if secondary_backend else None
        
    def _create_backend(self, backend_type: CacheBackend):
        """Create cache backend"""
        if backend_type == CacheBackend.MEMORY:
            return MemoryCache()
        elif backend_type == CacheBackend.FILE:
            return FileCache()
        # Add other backends as needed
        return MemoryCache()
        
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        # Try primary first
        value = self.primary.get(key)
        if value is not None:
            return value
            
        # Try secondary
        if self.secondary:
            value = self.secondary.get(key)
            if value is not None:
                # Promote to primary
                self.primary.set(key, value)
                return value
                
        return None
        
    def set(self, key: str, value: Any, ttl: Optional[int] = None,
           tags: Optional[List[str]] = None):
        """Set value in cache"""
        # Set in primary
        self.primary.set(key, value, ttl, tags)
        
        # Set in secondary
        if self.secondary:
            self.secondary.set(key, value, ttl, tags)
            
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        result = self.primary.delete(key)
        if self.secondary:
            result = self.secondary.delete(key) or result
        return result
        
    def clear(self):
        """Clear all cache entries"""
        self.primary.clear()
        if self.secondary:
            self.secondary.clear()


class CacheWarmer:
    """Cache warming system"""
    
    def __init__(self, cache):
        self.cache = cache
        self.warmup_functions = []
        self.warming_thread = None
        self.stop_warming = False
        
    def register_warmup(self, func: Callable, interval: int = 300):
        """Register cache warmup function"""
        self.warmup_functions.append((func, interval))
        
    def start_warming(self):
        """Start cache warming"""
        self.stop_warming = False
        self.warming_thread = threading.Thread(target=self._warming_loop)
        self.warming_thread.daemon = True
        self.warming_thread.start()
        
    def stop_warming(self):
        """Stop cache warming"""
        self.stop_warming = True
        if self.warming_thread:
            self.warming_thread.join(timeout=5)
            
    def _warming_loop(self):
        """Cache warming loop"""
        last_run = {}
        
        while not self.stop_warming:
            for func, interval in self.warmup_functions:
                func_name = func.__name__
                
                if func_name not in last_run:
                    last_run[func_name] = 0
                    
                if time.time() - last_run[func_name] >= interval:
                    try:
                        # Run warmup function
                        data = func()
                        
                        # Cache results
                        if isinstance(data, dict):
                            for key, value in data.items():
                                self.cache.set(key, value)
                                
                        last_run[func_name] = time.time()
                        
                    except Exception:
                        pass
                        
            time.sleep(10)  # Check every 10 seconds


class Cache:
    """Main cache interface"""
    
    def __init__(self, backend: CacheBackend = CacheBackend.MEMORY, **kwargs):
        self.backend_type = backend
        
        if backend == CacheBackend.MEMORY:
            self.backend = MemoryCache(**kwargs)
        elif backend == CacheBackend.FILE:
            self.backend = FileCache(**kwargs)
        elif backend == CacheBackend.HYBRID:
            self.backend = HybridCache(**kwargs)
        else:
            self.backend = MemoryCache(**kwargs)
            
        self.warmer = CacheWarmer(self.backend)
        
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        return self.backend.get(key)
        
    def set(self, key: str, value: Any, ttl: Optional[int] = None,
           tags: Optional[List[str]] = None):
        """Set value in cache"""
        self.backend.set(key, value, ttl, tags)
        
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        return self.backend.delete(key)
        
    def clear(self):
        """Clear all cache entries"""
        self.backend.clear()
        
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if hasattr(self.backend, 'stats'):
            return self.backend.stats.get_stats()
        return {}
        
    def cache_function(self, ttl: int = 300, key_prefix: str = ""):
        """Decorator for caching function results"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Generate cache key
                key_parts = [key_prefix, func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = ":".join(key_parts)
                
                # Try to get from cache
                result = self.get(cache_key)
                if result is not None:
                    return result
                    
                # Execute function
                result = func(*args, **kwargs)
                
                # Cache result
                self.set(cache_key, result, ttl)
                
                return result
            return wrapper
        return decorator


# Global cache instance
_cache = None


def get_cache() -> Cache:
    """Get global cache instance"""
    global _cache
    if _cache is None:
        _cache = Cache()
    return _cache


def init_cache(backend: CacheBackend = CacheBackend.MEMORY, **kwargs) -> Cache:
    """Initialize cache"""
    global _cache
    _cache = Cache(backend, **kwargs)
    return _cache