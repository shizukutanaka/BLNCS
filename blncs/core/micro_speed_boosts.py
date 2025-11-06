"""
BLNCS Micro Speed Boosts - Consolidated
This file has been merged into performance_optimizations.py
"""

import warnings
warnings.warn("micro_speed_boosts.py is deprecated. Use blncs.core.performance_optimizations instead.", DeprecationWarning, stacklevel=2)

# Redirect to unified performance optimizations
from blncs.core.performance_optimizations import (
    FastStringOperations as InlineOptimizations,
    FastDataStructures,
    benchmark,
    get_optimizer
)

__all__ = ['InlineOptimizations', 'FastDataStructures', 'benchmark', 'get_optimizer']