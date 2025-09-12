"""
Metrics System for BLNCS - Wrapper for lightweight implementation
Maintains compatibility while using optimized lightweight metrics.
"""

from .metrics_lightweight import (
    LightweightMetricsCollector,
    SystemMetricsCollector,
    get_metrics_collector as get_lightweight_metrics_collector,
    MetricPoint,
    TimingContext,
    counter,
    gauge,
    timer,
    timing,
    increment
)

# Re-export for compatibility
MetricsCollector = LightweightMetricsCollector

def get_metrics_collector():
    """Get metrics collector instance (compatibility wrapper)"""
    return get_lightweight_metrics_collector()

# For backward compatibility with existing code
def get_metrics_manager():
    """Get metrics manager (alias for collector)"""
    return get_metrics_collector()

__all__ = [
    'MetricsCollector', 'LightweightMetricsCollector', 'SystemMetricsCollector',
    'get_metrics_collector', 'get_metrics_manager', 'MetricPoint', 'TimingContext',
    'counter', 'gauge', 'timer', 'timing', 'increment'
]