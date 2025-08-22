# BLRCS Cache Module  
# High-performance in-memory cache with TTL support
import asyncio
import time
import hashlib
import json
import pickle
import zlib
from typing import Optional, Any, Dict, Union
from collections import OrderedDict
from threading import RLock
from dataclasses import dataclass

@dataclass
class CacheEntry:
    """Enhanced cache entry with metadata"""
    value: Any
    expiry: float
    size: int
    access_count: int = 0
    last_access: float = 0
    compressed: bool = False
    
    def __post_init__(self):
        self.last_access = time.time()

class EnhancedCache:
    """
    High-performance LRU cache with advanced features:
    - Automatic compression for large values
    - Memory-aware eviction
    - Access frequency tracking
    - Adaptive TTL based on usage patterns
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300, 
                 max_memory_mb: int = 100, compression_threshold: int = 1024):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.compression_threshold = compression_threshold
        
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._memory_evictions = 0
        self._total_memory = 0
        
        # Background cleanup task management
        self._cleanup_interval = 30  # More frequent cleanup
        self._stop_event: Optional[asyncio.Event] = None
        self._cleanup_task_handle: Optional[asyncio.Task] = None
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate memory size of object"""
        try:
            if isinstance(obj, (str, bytes)):
                return len(obj)
            elif isinstance(obj, (int, float)):
                return 8
            elif isinstance(obj, (list, tuple)):
                return sum(self._estimate_size(item) for item in obj)
            elif isinstance(obj, dict):
                return sum(self._estimate_size(k) + self._estimate_size(v) for k, v in obj.items())
            else:
                # Fallback to pickle size
                return len(pickle.dumps(obj))
        except:
            return 100  # Default estimate
    
    def _compress_value(self, value: Any) -> tuple[bytes, bool]:
        """Compress value if beneficial"""
        try:
            pickled = pickle.dumps(value)
            if len(pickled) > self.compression_threshold:
                compressed = zlib.compress(pickled, level=6)
                if len(compressed) < len(pickled) * 0.8:  # Only if 20%+ savings
                    return compressed, True
            return pickled, False
        except:
            return pickle.dumps(value), False
    
    def _decompress_value(self, data: bytes, is_compressed: bool) -> Any:
        """Decompress value"""
        try:
            if is_compressed:
                data = zlib.decompress(data)
            # セキュアなデシリアライズ - 安全なJSONフォーマット推奨
            import json
            try:
                return json.loads(data.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                # 後方互換性のためのフォールバック（警告付き）
                logger = get_logger(__name__)
                logger.warning("Using pickle for deserialization - consider migrating to JSON")
                return pickle.loads(data)
        except Exception as e:
            logger = get_logger(__name__)
            logger.debug(f"Cache deserialization failed: {e}")
            return None
    
    def _should_evict_by_frequency(self) -> Optional[str]:
        """Find least frequently used item for eviction"""
        if not self._cache:
            return None
        
        # Find item with lowest access_count/age ratio
        current_time = time.time()
        worst_key = None
        worst_score = float('inf')
        
        for key, entry in self._cache.items():
            age = current_time - entry.last_access
            if age == 0:
                age = 1  # Avoid division by zero
            score = entry.access_count / age
            if score < worst_score:
                worst_score = score
                worst_key = key
        
        return worst_key
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache with frequency tracking"""
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                
                if entry.expiry > time.time():
                    # Update access statistics
                    entry.access_count += 1
                    entry.last_access = time.time()
                    
                    # Move to end (LRU)
                    self._cache.move_to_end(key)
                    self._hits += 1
                    
                    # Decompress if needed
                    if entry.compressed:
                        return self._decompress_value(entry.value, True)
                    else:
                        return self._decompress_value(entry.value, False)
                else:
                    # Expired
                    self._total_memory -= entry.size
                    del self._cache[key]
            
            self._misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache with intelligent eviction"""
        ttl = ttl or self.default_ttl
        expiry = time.time() + ttl
        
        # Compress if beneficial
        compressed_value, is_compressed = self._compress_value(value)
        entry_size = len(compressed_value)
        
        with self._lock:
            # Remove existing entry if present
            if key in self._cache:
                old_entry = self._cache[key]
                self._total_memory -= old_entry.size
                del self._cache[key]
            
            # Memory-based eviction
            while (self._total_memory + entry_size > self.max_memory_bytes and 
                   len(self._cache) > 0):
                evict_key = self._should_evict_by_frequency()
                if evict_key:
                    evict_entry = self._cache[evict_key]
                    self._total_memory -= evict_entry.size
                    del self._cache[evict_key]
                    self._memory_evictions += 1
                else:
                    break
            
            # Size-based eviction
            while len(self._cache) >= self.max_size:
                _, evict_entry = self._cache.popitem(last=False)
                self._total_memory -= evict_entry.size
                self._evictions += 1
            
            # Create new entry
            entry = CacheEntry(
                value=compressed_value,
                expiry=expiry,
                size=entry_size,
                compressed=is_compressed
            )
            
            self._cache[key] = entry
            self._cache.move_to_end(key)
            self._total_memory += entry_size
    
    async def initialize(self):
        """Initialize enhanced cache and start cleanup task"""
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        self._cleanup_task_handle = asyncio.create_task(self._cleanup_task(), name="EnhancedCacheCleanup")

    async def stop(self):
        """Stop background cleanup task gracefully."""
        try:
            if self._stop_event is None:
                return
            self._stop_event.set()
            task = self._cleanup_task_handle
            if task and not task.done():
                try:
                    await asyncio.wait_for(task, timeout=2.0)
                except asyncio.TimeoutError:
                    task.cancel()
                    try:
                        await asyncio.gather(task, return_exceptions=True)
                    except Exception:
                        pass
        finally:
            self._cleanup_task_handle = None
            self._stop_event = None

    async def delete(self, key: str) -> bool:
        """Delete item from cache."""
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                self._total_memory -= entry.size
                del self._cache[key]
                return True
            return False

    async def clear(self):
        """Clear all items from cache"""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            self._memory_evictions = 0
            self._total_memory = 0

    async def cleanup(self):
        """Remove expired items from cache"""
        current_time = time.time()
        expired_keys = []
        
        with self._lock:
            for key, entry in self._cache.items():
                if entry.expiry <= current_time:
                    expired_keys.append(key)
            
            for key in expired_keys:
                entry = self._cache[key]
                self._total_memory -= entry.size
                del self._cache[key]
        
        return len(expired_keys)

    async def _cleanup_task(self):
        """Background task to periodically clean expired items"""
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        while not self._stop_event.is_set():
            try:
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self._cleanup_interval)
                except asyncio.TimeoutError:
                    pass
                if self._stop_event.is_set():
                    break
                expired_count = await self.cleanup()
                if expired_count > 0:
                    print(f"Enhanced cache cleanup: removed {expired_count} expired items")
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Enhanced cache cleanup error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get enhanced cache statistics"""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0
            memory_mb = self._total_memory / (1024 * 1024)
            
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "memory_mb": f"{memory_mb:.2f}",
                "max_memory_mb": self.max_memory_bytes / (1024 * 1024),
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "memory_evictions": self._memory_evictions,
                "hit_rate": f"{hit_rate:.2%}",
                "total_requests": total_requests
            }

    def health_check(self) -> bool:
        """Check enhanced cache health"""
        try:
            with self._lock:
                return (len(self._cache) <= self.max_size and 
                       self._total_memory <= self.max_memory_bytes)
        except:
            return False

class Cache:
    """Thread-safe LRU cache with TTL support."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        # Background cleanup task management
        self._cleanup_interval = 60
        self._stop_event: Optional[asyncio.Event] = None
        self._cleanup_task_handle: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize cache and start cleanup task"""
        # Lazily create the stop event in the running loop
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        # Start background cleanup loop and keep handle for shutdown
        self._cleanup_task_handle = asyncio.create_task(self._cleanup_task(), name="CacheCleanup")

    async def stop(self):
        """Stop background cleanup task gracefully."""
        try:
            if self._stop_event is None:
                # Not started or already stopped
                return
            # Signal the cleanup task to exit and await it
            self._stop_event.set()
            task = self._cleanup_task_handle
            if task and not task.done():
                try:
                    await asyncio.wait_for(task, timeout=2.0)
                except asyncio.TimeoutError:
                    # Fallback to cancellation if it doesn't exit promptly
                    task.cancel()
                    try:
                        await asyncio.gather(task, return_exceptions=True)
                    except Exception:
                        pass
        finally:
            self._cleanup_task_handle = None
            self._stop_event = None
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            if key in self._cache:
                value, expiry = self._cache[key]
                
                if expiry > time.time():
                    self._cache.move_to_end(key)
                    self._hits += 1
                    return value
                else:
                    del self._cache[key]
            
            self._misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache."""
        ttl = ttl or self.default_ttl
        expiry = time.time() + ttl
        
        with self._lock:
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
                self._evictions += 1
            
            self._cache[key] = (value, expiry)
            self._cache.move_to_end(key)
    
    async def delete(self, key: str) -> bool:
        """Delete item from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    async def clear(self):
        """Clear all items from cache"""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
    
    async def cleanup(self):
        """Remove expired items from cache"""
        current_time = time.time()
        expired_keys = []
        
        with self._lock:
            for key, (_, expiry) in self._cache.items():
                if expiry <= current_time:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._cache[key]
        
        return len(expired_keys)
    
    async def _cleanup_task(self):
        """Background task to periodically clean expired items"""
        # Ensure event exists
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        while not self._stop_event.is_set():
            try:
                # Wait for either stop signal or timeout interval
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self._cleanup_interval)
                except asyncio.TimeoutError:
                    pass
                if self._stop_event.is_set():
                    break
                expired_count = await self.cleanup()
                if expired_count > 0:
                    print(f"Cache cleanup: removed {expired_count} expired items")
            except asyncio.CancelledError:
                # Task was cancelled during shutdown
                break
            except Exception as e:
                print(f"Cache cleanup error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0
            
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_rate": f"{hit_rate:.2%}",
                "total_requests": total_requests
            }
    
    def health_check(self) -> bool:
        """Check cache health"""
        try:
            with self._lock:
                return len(self._cache) <= self.max_size
        except:
            return False

class RateLimitCache:
    """Specialized cache for rate limiting."""
    
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self._requests: Dict[str, list[float]] = {}
        self._lock = RLock()
    
    def check_and_increment(self, key: str, limit: int) -> bool:
        """Check if request is within rate limit and increment counter."""
        current_time = time.time()
        window_start = current_time - self.window_size
        
        with self._lock:
            if key not in self._requests:
                self._requests[key] = []
            
            self._requests[key] = [
                t for t in self._requests[key] 
                if t > window_start
            ]
            
            if len(self._requests[key]) >= limit:
                return False
            
            self._requests[key].append(current_time)
            return True
    
    def get_remaining(self, key: str, limit: int) -> int:
        """Get remaining requests for key"""
        current_time = time.time()
        window_start = current_time - self.window_size
        
        with self._lock:
            if key not in self._requests:
                return limit
            
            count = sum(1 for t in self._requests[key] if t > window_start)
            return max(0, limit - count)
