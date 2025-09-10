"""
Fee optimizer module - compatibility layer for fee_optimizer_advanced
"""

from .fee_optimizer_advanced import (
    get_advanced_fee_optimizer,
    get_fee_optimizer as get_fee_optimizer_advanced,
    AdvancedFeeOptimizer,
    FeeRecommendation,
    ChannelMetrics
)

# Alias for backward compatibility
FeeOptimizer = AdvancedFeeOptimizer

def get_fee_optimizer():
    """Get the fee optimizer instance (backward compatibility)"""
    return get_advanced_fee_optimizer()

# Re-export commonly used items
__all__ = [
    'FeeOptimizer',
    'get_fee_optimizer',
    'FeeRecommendation',
    'ChannelMetrics'
]