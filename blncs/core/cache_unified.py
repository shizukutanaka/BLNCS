"""
Cache System for BLNCS - Wrapper for simple cache implementation
Maintains compatibility while using lightweight cache system.
"""

from .cache_simple import (
    SimpleCache, 
    cached,
    get_cache as get_simple_cache,
    get_typed_cache as get_simple_typed_cache,
    CacheEntry
)

# Re-export for compatibility
UnifiedCache = SimpleCache

def get_cache():
    """Get cache instance (compatibility wrapper)"""
    return get_simple_cache()

def get_typed_cache(cache_type: str = 'default'):
    """Get typed cache instance (compatibility wrapper)"""
    return get_simple_typed_cache(cache_type)

__all__ = ['UnifiedCache', 'SimpleCache', 'cached', 'get_cache', 'get_typed_cache', 'CacheEntry']