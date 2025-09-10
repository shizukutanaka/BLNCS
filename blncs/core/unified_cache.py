"""
Unified Caching Strategy for BLNCS
Centralizes all caching operations with consistent TTL policies and memory management.
"""

import time
from typing import Any, Optional, Dict, Callable, TypeVar, Protocol
from functools import wraps
import threading
from dataclasses import dataclass
from enum import Enum

from .fast_cache import FastCache
from .logger import get_logger


class CacheType(Enum):
    """Cache types with specific use cases"""
    LIGHTNING_DATA = "lightning_data"       # Node info, channels - 5 min TTL
    CONFIGURATION = "configuration"        # Config values - 15 min TTL  
    NETWORK_REQUESTS = "network_requests"   # API responses - 1 min TTL
    CALCULATIONS = "calculations"          # Fee calculations - 10 min TTL
    SYSTEM_STATUS = "system_status"        # Health checks - 30 sec TTL


@dataclass
class CacheConfig:
    """Configuration for cache types"""
    ttl: int
    max_size: int
    description: str


T = TypeVar('T')


class CacheProtocol(Protocol):
    """Protocol for cache implementations"""
    def get(self, key: str, default: Any = None) -> Any:
        ...
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        ...
    
    def clear(self) -> None:
        ...


class UnifiedCacheManager:
    """Centralized cache management with type-specific policies"""
    
    # Cache configurations by type
    CACHE_CONFIGS = {
        CacheType.LIGHTNING_DATA: CacheConfig(ttl=300, max_size=512, description="Lightning Network data"),
        CacheType.CONFIGURATION: CacheConfig(ttl=900, max_size=128, description="Configuration values"),
        CacheType.NETWORK_REQUESTS: CacheConfig(ttl=60, max_size=256, description="Network API responses"),
        CacheType.CALCULATIONS: CacheConfig(ttl=600, max_size=1024, description="Fee and routing calculations"),
        CacheType.SYSTEM_STATUS: CacheConfig(ttl=30, max_size=64, description="System health status")
    }
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._caches: Dict[CacheType, FastCache] = {}
        self._lock = threading.RLock()
        self._initialize_caches()
        
        # Statistics
        self._total_hits = 0
        self._total_misses = 0
    
    def _initialize_caches(self):
        """Initialize type-specific caches"""
        for cache_type, config in self.CACHE_CONFIGS.items():
            self._caches[cache_type] = FastCache(
                max_size=config.max_size,
                default_ttl=config.ttl
            )
            self.logger.debug(f"Initialized {cache_type.value} cache: {config.description}")
    
    def get(self, cache_type: CacheType, key: str, default: Any = None) -> Any:
        """Get value from specific cache type"""
        cache = self._caches.get(cache_type)
        if not cache:
            return default
        
        value = cache.get(key, default)
        with self._lock:
            if value != default:
                self._total_hits += 1
            else:
                self._total_misses += 1
        
        return value
    
    def set(self, cache_type: CacheType, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in specific cache type"""
        cache = self._caches.get(cache_type)
        if cache:
            cache.set(key, value, ttl)
    
    def clear_cache_type(self, cache_type: CacheType) -> None:
        """Clear all entries for specific cache type"""
        cache = self._caches.get(cache_type)
        if cache:
            cache.clear()
            self.logger.info(f"Cleared {cache_type.value} cache")
    
    def clear_all(self) -> None:
        """Clear all caches"""
        for cache_type in self._caches:
            self.clear_cache_type(cache_type)
        
        with self._lock:
            self._total_hits = 0
            self._total_misses = 0
        
        self.logger.info("Cleared all caches")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self._total_hits + self._total_misses
            hit_rate = (self._total_hits / total_requests * 100) if total_requests > 0 else 0
            
            cache_stats = {}
            for cache_type, cache in self._caches.items():
                cache_stats[cache_type.value] = {
                    'hits': getattr(cache, '_hits', 0),
                    'misses': getattr(cache, '_misses', 0),
                    'size': len(getattr(cache, '_cache', {})),
                    'max_size': cache.max_size,
                    'default_ttl': cache.default_ttl
                }
            
            return {
                'global_hit_rate': f"{hit_rate:.1f}%",
                'total_hits': self._total_hits,
                'total_misses': self._total_misses,
                'cache_types': cache_stats
            }
    
    def cache_decorator(self, cache_type: CacheType, key_prefix: str = "", ttl: Optional[int] = None):
        """Decorator for automatic caching"""
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @wraps(func)
            def wrapper(*args, **kwargs) -> T:
                # Generate cache key
                cache_key = f"{key_prefix}{func.__name__}:"
                if args:
                    cache_key += f"args_{hash(str(args))}"
                if kwargs:
                    cache_key += f"kwargs_{hash(str(sorted(kwargs.items())))}"
                
                # Try to get from cache
                cached_result = self.get(cache_type, cache_key)
                if cached_result is not None:
                    return cached_result
                
                # Execute function and cache result
                result = func(*args, **kwargs)
                self.set(cache_type, cache_key, result, ttl)
                return result
            
            return wrapper
        return decorator


# Global cache manager instance
_cache_manager: Optional[UnifiedCacheManager] = None
_cache_lock = threading.Lock()


def get_cache_manager() -> UnifiedCacheManager:
    """Get global cache manager instance"""
    global _cache_manager
    if _cache_manager is None:
        with _cache_lock:
            if _cache_manager is None:
                _cache_manager = UnifiedCacheManager()
    return _cache_manager


# Convenience functions for common cache operations
def cache_lightning_data(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Cache Lightning Network data"""
    get_cache_manager().set(CacheType.LIGHTNING_DATA, key, value, ttl)


def get_lightning_data(key: str, default: Any = None) -> Any:
    """Get cached Lightning Network data"""
    return get_cache_manager().get(CacheType.LIGHTNING_DATA, key, default)


def cache_config_value(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Cache configuration value"""
    get_cache_manager().set(CacheType.CONFIGURATION, key, value, ttl)


def get_config_value(key: str, default: Any = None) -> Any:
    """Get cached configuration value"""
    return get_cache_manager().get(CacheType.CONFIGURATION, key, default)


def cache_network_response(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Cache network API response"""
    get_cache_manager().set(CacheType.NETWORK_REQUESTS, key, value, ttl)


def get_network_response(key: str, default: Any = None) -> Any:
    """Get cached network API response"""
    return get_cache_manager().get(CacheType.NETWORK_REQUESTS, key, default)


def cache_calculation(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Cache calculation result"""
    get_cache_manager().set(CacheType.CALCULATIONS, key, value, ttl)


def get_calculation(key: str, default: Any = None) -> Any:
    """Get cached calculation result"""
    return get_cache_manager().get(CacheType.CALCULATIONS, key, default)


# Decorators for automatic caching
def cache_lightning(ttl: Optional[int] = None, key_prefix: str = ""):
    """Decorator for caching Lightning Network operations"""
    return get_cache_manager().cache_decorator(CacheType.LIGHTNING_DATA, key_prefix, ttl)


def cache_config(ttl: Optional[int] = None, key_prefix: str = ""):
    """Decorator for caching configuration operations"""
    return get_cache_manager().cache_decorator(CacheType.CONFIGURATION, key_prefix, ttl)


def cache_network(ttl: Optional[int] = None, key_prefix: str = ""):
    """Decorator for caching network operations"""
    return get_cache_manager().cache_decorator(CacheType.NETWORK_REQUESTS, key_prefix, ttl)


def cache_calc(ttl: Optional[int] = None, key_prefix: str = ""):
    """Decorator for caching calculations"""
    return get_cache_manager().cache_decorator(CacheType.CALCULATIONS, key_prefix, ttl)


def cache_status(ttl: Optional[int] = None, key_prefix: str = ""):
    """Decorator for caching system status"""
    return get_cache_manager().cache_decorator(CacheType.SYSTEM_STATUS, key_prefix, ttl)