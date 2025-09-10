"""
Unified Cache - Backward compatibility wrapper
Redirects to the new unified cache system.
"""

from .cache_unified import (
    get_cache,
    get_cache_manager,
    get_typed_cache,
    CacheStrategy,
    CacheEntry,
    UnifiedCache,
    TypedCache,
    cached,
    memoize
)

# For backward compatibility with CacheType enum
from enum import Enum

class CacheType(Enum):
    """Legacy cache type enum for backward compatibility."""
    LIGHTNING_DATA = "lightning"
    CONFIGURATION = "config"
    NETWORK_REQUESTS = "api"
    CALCULATIONS = "metrics"
    SYSTEM_STATUS = "general"

# Re-export everything
__all__ = [
    'get_cache',
    'get_cache_manager',
    'get_typed_cache',
    'CacheStrategy',
    'CacheEntry',
    'CacheType',
    'UnifiedCache',
    'TypedCache',
    'cached',
    'memoize'
]