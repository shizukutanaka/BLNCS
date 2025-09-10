"""
Fast Cache - Backward compatibility wrapper
Redirects to the unified cache system.
"""

from .cache_unified import (
    get_cache,
    get_typed_cache,
    get_cache_manager,
    get_fast_cache as _get_fast_cache,
    cached,
    memoize,
    UnifiedCache,
    TypedCache,
    CacheStrategy,
    CacheEntry
)

# Legacy function names
def get_fast_cache():
    """Get fast cache (backward compatibility)."""
    return get_cache()

# Legacy decorator
fast_cache = cached

# Re-export everything for backward compatibility
__all__ = [
    'get_cache',
    'get_fast_cache',
    'get_cache_manager',
    'get_typed_cache',
    'cached',
    'fast_cache',
    'memoize',
    'UnifiedCache',
    'TypedCache', 
    'CacheStrategy',
    'CacheEntry'
]