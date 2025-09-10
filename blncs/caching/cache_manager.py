"""
Advanced Multi-Tier Caching System
Redis Cluster, intelligent cache warming, compression, and distributed cache management.
"""

import asyncio
import json
import logging
import time
import zlib
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict, OrderedDict
import aioredis
from rediscluster import RedisCluster
import pickle
import structlog

logger = structlog.get_logger(__name__)

class CacheStrategy(Enum):
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In First Out
    TTL = "ttl"  # Time To Live based
    ADAPTIVE = "adaptive"  # Adaptive replacement

class CacheTier(Enum):
    L1_MEMORY = "l1_memory"
    L2_REDIS = "l2_redis"
    L3_DISK = "l3_disk"
    L4_REMOTE = "l4_remote"

class CompressionType(Enum):
    NONE = "none"
    GZIP = "gzip"
    LZ4 = "lz4"
    SNAPPY = "snappy"

@dataclass
class CacheConfig:
    redis_cluster_nodes: List[str] = field(default_factory=lambda: ["localhost:7000", "localhost:7001", "localhost:7002"])
    redis_password: Optional[str] = None
    l1_max_size: int = 1000  # In-memory cache size
    l1_ttl_seconds: int = 300  # 5 minutes
    l2_ttl_seconds: int = 3600  # 1 hour
    l3_ttl_seconds: int = 86400  # 24 hours
    default_strategy: CacheStrategy = CacheStrategy.LRU
    compression_enabled: bool = True
    compression_type: CompressionType = CompressionType.GZIP
    compression_threshold: int = 1024  # Compress if size > 1KB
    enable_cache_warming: bool = True
    enable_metrics: bool = True
    batch_size: int = 100
    connection_pool_size: int = 20
    key_prefix: str = "blncs"
    enable_clustering: bool = True

@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    memory_usage: int = 0
    hit_rate: float = 0.0
    average_response_time: float = 0.0
    compression_ratio: float = 0.0

class MemoryCache:
    def __init__(self, max_size: int, strategy: CacheStrategy, ttl_seconds: int):
        self.max_size = max_size
        self.strategy = strategy
        self.ttl_seconds = ttl_seconds
        self.cache = OrderedDict()
        self.access_times = {}
        self.access_counts = defaultdict(int)
        self.lock = threading.RLock()
        self.stats = CacheStats()
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from memory cache"""
        with self.lock:
            if key not in self.cache:
                self.stats.misses += 1
                return None
            
            # Check TTL
            item = self.cache[key]
            if time.time() > item['expires_at']:
                del self.cache[key]
                self.access_times.pop(key, None)
                self.stats.misses += 1
                return None
            
            # Update access tracking
            self._update_access(key)
            self.stats.hits += 1
            
            return item['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set item in memory cache"""
        with self.lock:
            expires_at = time.time() + (ttl or self.ttl_seconds)
            
            # Evict if necessary
            while len(self.cache) >= self.max_size and key not in self.cache:
                self._evict_item()
            
            self.cache[key] = {
                'value': value,
                'expires_at': expires_at,
                'created_at': time.time()
            }
            
            self._update_access(key)
            self._update_stats()
            
            return True
    
    def delete(self, key: str) -> bool:
        """Delete item from memory cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                self.access_times.pop(key, None)
                self.access_counts.pop(key, 0)
                self._update_stats()
                return True
            return False
    
    def _update_access(self, key: str):
        """Update access tracking"""
        current_time = time.time()
        self.access_times[key] = current_time
        self.access_counts[key] += 1
        
        # Move to end for LRU
        if self.strategy == CacheStrategy.LRU:
            self.cache.move_to_end(key)
    
    def _evict_item(self):
        """Evict item based on strategy"""
        if not self.cache:
            return
        
        if self.strategy == CacheStrategy.LRU:
            # Remove least recently used
            key = next(iter(self.cache))
        elif self.strategy == CacheStrategy.LFU:
            # Remove least frequently used
            key = min(self.access_counts.keys(), key=lambda k: self.access_counts[k])
        elif self.strategy == CacheStrategy.FIFO:
            # Remove first in
            key = next(iter(self.cache))
        else:
            # Default to LRU
            key = next(iter(self.cache))
        
        del self.cache[key]
        self.access_times.pop(key, None)
        self.access_counts.pop(key, 0)
        self.stats.evictions += 1
    
    def _update_stats(self):
        """Update cache statistics"""
        self.stats.size = len(self.cache)
        self.stats.memory_usage = sum(len(pickle.dumps(item)) for item in self.cache.values())
        
        total_requests = self.stats.hits + self.stats.misses
        if total_requests > 0:
            self.stats.hit_rate = self.stats.hits / total_requests
    
    def clear(self):
        """Clear all cache items"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            self.access_counts.clear()
            self.stats = CacheStats()

class CacheCompressionManager:
    def __init__(self, compression_type: CompressionType, threshold: int):
        self.compression_type = compression_type
        self.threshold = threshold
    
    def compress(self, data: bytes) -> Tuple[bytes, bool]:
        """Compress data if above threshold"""
        if len(data) < self.threshold or self.compression_type == CompressionType.NONE:
            return data, False
        
        try:
            if self.compression_type == CompressionType.GZIP:
                compressed = zlib.compress(data)
            else:
                # Default to gzip for unsupported types
                compressed = zlib.compress(data)
            
            # Only use compressed if it's actually smaller
            if len(compressed) < len(data):
                return compressed, True
            else:
                return data, False
                
        except Exception as e:
            logger.warning(f"Compression failed: {e}")
            return data, False
    
    def decompress(self, data: bytes, is_compressed: bool) -> bytes:
        """Decompress data if compressed"""
        if not is_compressed:
            return data
        
        try:
            if self.compression_type == CompressionType.GZIP:
                return zlib.decompress(data)
            else:
                return zlib.decompress(data)
                
        except Exception as e:
            logger.error(f"Decompression failed: {e}")
            return data

class DistributedCache:
    def __init__(self, config: CacheConfig):
        self.config = config
        self.redis_cluster = None
        self.redis_client = None
        self.compression_manager = CacheCompressionManager(
            config.compression_type, 
            config.compression_threshold
        )
        self.stats = CacheStats()
    
    async def initialize(self):
        """Initialize Redis cluster connection"""
        try:
            if self.config.enable_clustering:
                # Initialize Redis Cluster
                startup_nodes = []
                for node in self.config.redis_cluster_nodes:
                    host, port = node.split(':')
                    startup_nodes.append({"host": host, "port": int(port)})
                
                self.redis_cluster = RedisCluster(
                    startup_nodes=startup_nodes,
                    password=self.config.redis_password,
                    decode_responses=False,  # We handle encoding ourselves
                    skip_full_coverage_check=True
                )
            else:
                # Single Redis instance
                node = self.config.redis_cluster_nodes[0]
                host, port = node.split(':')
                self.redis_client = aioredis.Redis(
                    host=host,
                    port=int(port),
                    password=self.config.redis_password,
                    decode_responses=False
                )
            
            logger.info("Distributed cache initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize distributed cache: {e}")
            raise
    
    async def get(self, key: str) -> Optional[Any]:
        """Get item from distributed cache"""
        try:
            start_time = time.time()
            full_key = f"{self.config.key_prefix}:{key}"
            
            # Get data and metadata
            if self.redis_cluster:
                pipe = self.redis_cluster.pipeline()
                pipe.get(full_key)
                pipe.hget(f"{full_key}:meta", "compressed")
                results = pipe.execute()
                data, is_compressed_str = results
            else:
                data = await self.redis_client.get(full_key)
                is_compressed_str = await self.redis_client.hget(f"{full_key}:meta", "compressed")
            
            if data is None:
                self.stats.misses += 1
                return None
            
            # Decompress if necessary
            is_compressed = is_compressed_str == b'1' if is_compressed_str else False
            decompressed_data = self.compression_manager.decompress(data, is_compressed)
            
            # Deserialize
            value = pickle.loads(decompressed_data)
            
            # Update stats
            self.stats.hits += 1
            response_time = (time.time() - start_time) * 1000
            self._update_response_time(response_time)
            
            return value
            
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self.stats.misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set item in distributed cache"""
        try:
            full_key = f"{self.config.key_prefix}:{key}"
            ttl_seconds = ttl or self.config.l2_ttl_seconds
            
            # Serialize
            serialized_data = pickle.dumps(value)
            
            # Compress if necessary
            compressed_data, is_compressed = self.compression_manager.compress(serialized_data)
            
            # Store data and metadata
            if self.redis_cluster:
                pipe = self.redis_cluster.pipeline()
                pipe.setex(full_key, ttl_seconds, compressed_data)
                pipe.hset(f"{full_key}:meta", "compressed", "1" if is_compressed else "0")
                pipe.expire(f"{full_key}:meta", ttl_seconds)
                pipe.execute()
            else:
                await self.redis_client.setex(full_key, ttl_seconds, compressed_data)
                await self.redis_client.hset(f"{full_key}:meta", "compressed", "1" if is_compressed else "0")
                await self.redis_client.expire(f"{full_key}:meta", ttl_seconds)
            
            # Update compression stats
            if self.config.compression_enabled and len(serialized_data) > 0:
                compression_ratio = len(compressed_data) / len(serialized_data)
                self._update_compression_ratio(compression_ratio)
            
            return True
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete item from distributed cache"""
        try:
            full_key = f"{self.config.key_prefix}:{key}"
            
            if self.redis_cluster:
                pipe = self.redis_cluster.pipeline()
                pipe.delete(full_key)
                pipe.delete(f"{full_key}:meta")
                results = pipe.execute()
                return results[0] > 0
            else:
                deleted = await self.redis_client.delete(full_key)
                await self.redis_client.delete(f"{full_key}:meta")
                return deleted > 0
                
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    async def batch_get(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple items from cache"""
        results = {}
        full_keys = [f"{self.config.key_prefix}:{key}" for key in keys]
        
        try:
            if self.redis_cluster:
                # For cluster, we need to handle cross-slot operations carefully
                for i, key in enumerate(keys):
                    value = await self.get(key)
                    if value is not None:
                        results[key] = value
            else:
                # Single instance can handle mget
                values = await self.redis_client.mget(full_keys)
                for i, value in enumerate(values):
                    if value is not None:
                        try:
                            results[keys[i]] = pickle.loads(value)
                        except Exception as e:
                            logger.warning(f"Failed to deserialize cached value for {keys[i]}: {e}")
            
        except Exception as e:
            logger.error(f"Batch get error: {e}")
        
        return results
    
    async def batch_set(self, items: Dict[str, Any], ttl: Optional[int] = None) -> int:
        """Set multiple items in cache"""
        success_count = 0
        ttl_seconds = ttl or self.config.l2_ttl_seconds
        
        try:
            if self.redis_cluster:
                # For cluster, set items individually
                for key, value in items.items():
                    if await self.set(key, value, ttl):
                        success_count += 1
            else:
                # Single instance can use pipeline
                pipe = self.redis_client.pipeline()
                
                for key, value in items.items():
                    full_key = f"{self.config.key_prefix}:{key}"
                    serialized_data = pickle.dumps(value)
                    compressed_data, is_compressed = self.compression_manager.compress(serialized_data)
                    
                    pipe.setex(full_key, ttl_seconds, compressed_data)
                    pipe.hset(f"{full_key}:meta", "compressed", "1" if is_compressed else "0")
                    pipe.expire(f"{full_key}:meta", ttl_seconds)
                
                await pipe.execute()
                success_count = len(items)
                
        except Exception as e:
            logger.error(f"Batch set error: {e}")
        
        return success_count
    
    def _update_response_time(self, response_time: float):
        """Update average response time"""
        if self.stats.average_response_time == 0:
            self.stats.average_response_time = response_time
        else:
            # Exponential moving average
            self.stats.average_response_time = (self.stats.average_response_time * 0.9) + (response_time * 0.1)
    
    def _update_compression_ratio(self, ratio: float):
        """Update compression ratio"""
        if self.stats.compression_ratio == 0:
            self.stats.compression_ratio = ratio
        else:
            self.stats.compression_ratio = (self.stats.compression_ratio * 0.9) + (ratio * 0.1)
    
    async def close(self):
        """Close Redis connections"""
        if self.redis_cluster:
            self.redis_cluster.connection_pool.disconnect()
        
        if self.redis_client:
            await self.redis_client.close()

class CacheWarmupManager:
    def __init__(self, cache_manager: 'CacheManager'):
        self.cache_manager = cache_manager
        self.warmup_tasks = {}
        self.warmup_patterns = []
    
    def add_warmup_pattern(self, pattern: str, data_loader: Callable[[], Dict[str, Any]], 
                          interval_minutes: int = 60):
        """Add cache warmup pattern"""
        self.warmup_patterns.append({
            'pattern': pattern,
            'data_loader': data_loader,
            'interval_minutes': interval_minutes,
            'last_run': None
        })
    
    async def start_warmup_scheduler(self):
        """Start cache warmup scheduler"""
        for pattern_info in self.warmup_patterns:
            task = asyncio.create_task(self._warmup_loop(pattern_info))
            self.warmup_tasks[pattern_info['pattern']] = task
    
    async def _warmup_loop(self, pattern_info: Dict[str, Any]):
        """Cache warmup loop"""
        while True:
            try:
                now = datetime.utcnow()
                last_run = pattern_info['last_run']
                
                should_run = (
                    last_run is None or 
                    (now - last_run).total_seconds() >= pattern_info['interval_minutes'] * 60
                )
                
                if should_run:
                    logger.info(f"Starting cache warmup for pattern: {pattern_info['pattern']}")
                    
                    # Load data
                    data_loader = pattern_info['data_loader']
                    if asyncio.iscoroutinefunction(data_loader):
                        data = await data_loader()
                    else:
                        data = data_loader()
                    
                    # Warm cache
                    if isinstance(data, dict):
                        await self.cache_manager.batch_set(data)
                        logger.info(f"Cache warmed with {len(data)} items for pattern: {pattern_info['pattern']}")
                    
                    pattern_info['last_run'] = now
                
                # Sleep for 1 minute before next check
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Cache warmup error for pattern {pattern_info['pattern']}: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
    
    def stop_warmup_scheduler(self):
        """Stop cache warmup scheduler"""
        for task in self.warmup_tasks.values():
            task.cancel()
        self.warmup_tasks.clear()

class CacheInvalidationManager:
    def __init__(self, cache_manager: 'CacheManager'):
        self.cache_manager = cache_manager
        self.invalidation_patterns = defaultdict(list)
        self.tag_mappings = defaultdict(set)
    
    def register_invalidation_pattern(self, event_type: str, key_pattern: str):
        """Register cache invalidation pattern"""
        self.invalidation_patterns[event_type].append(key_pattern)
    
    def tag_cache_key(self, key: str, tags: List[str]):
        """Associate tags with cache key"""
        for tag in tags:
            self.tag_mappings[tag].add(key)
    
    async def handle_invalidation_event(self, event_type: str, event_data: Dict[str, Any]):
        """Handle cache invalidation event"""
        patterns = self.invalidation_patterns.get(event_type, [])
        
        for pattern in patterns:
            # Simple pattern matching - in production, use more sophisticated matching
            keys_to_invalidate = self._match_pattern(pattern, event_data)
            
            for key in keys_to_invalidate:
                await self.cache_manager.delete(key)
                logger.debug(f"Invalidated cache key: {key}")
    
    async def invalidate_by_tag(self, tag: str):
        """Invalidate all cache keys with specific tag"""
        if tag in self.tag_mappings:
            keys_to_invalidate = list(self.tag_mappings[tag])
            
            for key in keys_to_invalidate:
                await self.cache_manager.delete(key)
            
            # Clear tag mapping
            del self.tag_mappings[tag]
            
            logger.info(f"Invalidated {len(keys_to_invalidate)} cache keys with tag: {tag}")
    
    def _match_pattern(self, pattern: str, event_data: Dict[str, Any]) -> List[str]:
        """Match pattern against event data"""
        # Simple implementation - in production, use regex or glob patterns
        matched_keys = []
        
        # Example: pattern "user:{user_id}:*" with event_data {"user_id": 123}
        if "{user_id}" in pattern and "user_id" in event_data:
            key_prefix = pattern.replace("{user_id}", str(event_data["user_id"]))
            matched_keys.append(key_prefix)
        
        return matched_keys

class CacheManager:
    def __init__(self, config: CacheConfig):
        self.config = config
        self.l1_cache = MemoryCache(
            config.l1_max_size,
            config.default_strategy,
            config.l1_ttl_seconds
        )
        self.l2_cache = DistributedCache(config)
        self.warmup_manager = CacheWarmupManager(self) if config.enable_cache_warming else None
        self.invalidation_manager = CacheInvalidationManager(self)
        self.initialized = False
    
    async def initialize(self):
        """Initialize cache manager"""
        try:
            await self.l2_cache.initialize()
            
            if self.warmup_manager:
                await self.warmup_manager.start_warmup_scheduler()
            
            self.initialized = True
            logger.info("Cache manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize cache manager: {e}")
            raise
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get item from multi-tier cache"""
        if not self.initialized:
            return default
        
        try:
            # Try L1 (memory) cache first
            value = self.l1_cache.get(key)
            if value is not None:
                return value
            
            # Try L2 (Redis) cache
            value = await self.l2_cache.get(key)
            if value is not None:
                # Promote to L1 cache
                self.l1_cache.set(key, value)
                return value
            
            return default
            
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return default
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None, tags: List[str] = None) -> bool:
        """Set item in multi-tier cache"""
        if not self.initialized:
            return False
        
        try:
            # Set in both L1 and L2 caches
            l1_success = self.l1_cache.set(key, value, ttl)
            l2_success = await self.l2_cache.set(key, value, ttl)
            
            # Register cache tags
            if tags and self.invalidation_manager:
                self.invalidation_manager.tag_cache_key(key, tags)
            
            return l1_success or l2_success
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete item from all cache tiers"""
        if not self.initialized:
            return False
        
        try:
            l1_success = self.l1_cache.delete(key)
            l2_success = await self.l2_cache.delete(key)
            
            return l1_success or l2_success
            
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    async def batch_get(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple items from cache"""
        if not self.initialized:
            return {}
        
        results = {}
        missing_keys = []
        
        # Check L1 cache first
        for key in keys:
            value = self.l1_cache.get(key)
            if value is not None:
                results[key] = value
            else:
                missing_keys.append(key)
        
        # Get missing keys from L2 cache
        if missing_keys:
            l2_results = await self.l2_cache.batch_get(missing_keys)
            
            # Promote L2 hits to L1 cache
            for key, value in l2_results.items():
                self.l1_cache.set(key, value)
                results[key] = value
        
        return results
    
    async def batch_set(self, items: Dict[str, Any], ttl: Optional[int] = None) -> int:
        """Set multiple items in cache"""
        if not self.initialized:
            return 0
        
        try:
            # Set in L1 cache
            l1_success = 0
            for key, value in items.items():
                if self.l1_cache.set(key, value, ttl):
                    l1_success += 1
            
            # Set in L2 cache
            l2_success = await self.l2_cache.batch_set(items, ttl)
            
            return max(l1_success, l2_success)
            
        except Exception as e:
            logger.error(f"Batch set error: {e}")
            return 0
    
    async def clear_cache(self, pattern: str = None):
        """Clear cache items"""
        if not self.initialized:
            return
        
        try:
            # Clear L1 cache
            if pattern is None:
                self.l1_cache.clear()
            # Pattern-based clearing would need more sophisticated implementation
            
            logger.info("Cache cleared")
            
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
    
    def get_stats(self) -> Dict[str, CacheStats]:
        """Get cache statistics"""
        stats = {
            'l1_memory': self.l1_cache.stats,
            'l2_redis': self.l2_cache.stats
        }
        
        # Calculate combined stats
        combined = CacheStats()
        combined.hits = self.l1_cache.stats.hits + self.l2_cache.stats.hits
        combined.misses = self.l1_cache.stats.misses + self.l2_cache.stats.misses
        
        total_requests = combined.hits + combined.misses
        if total_requests > 0:
            combined.hit_rate = combined.hits / total_requests
        
        stats['combined'] = combined
        
        return stats
    
    async def shutdown(self):
        """Shutdown cache manager"""
        if self.warmup_manager:
            self.warmup_manager.stop_warmup_scheduler()
        
        await self.l2_cache.close()
        self.l1_cache.clear()
        
        logger.info("Cache manager shutdown completed")

# Global cache manager instance
_cache_manager_instance = None

async def get_cache_manager(config: Optional[CacheConfig] = None) -> CacheManager:
    """Get or create cache manager"""
    global _cache_manager_instance
    
    if _cache_manager_instance is None:
        if config is None:
            config = CacheConfig()
        
        _cache_manager_instance = CacheManager(config)
        await _cache_manager_instance.initialize()
    
    return _cache_manager_instance

async def initialize_caching(config: CacheConfig) -> CacheManager:
    """Initialize caching with custom config"""
    manager = CacheManager(config)
    await manager.initialize()
    return manager