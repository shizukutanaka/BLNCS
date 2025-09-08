"""
Monitoring Operations Module
Simple interface functions for monitoring operations.
"""

from .unified_monitor import UnifiedMonitor

# Global monitor instance
_global_unified_monitor = None


def get_performance_monitor() -> UnifiedMonitor:
    """Get global unified monitor (backward compatibility)"""
    global _global_unified_monitor
    if _global_unified_monitor is None:
        _global_unified_monitor = UnifiedMonitor()
    return _global_unified_monitor


def get_wallet_monitor() -> UnifiedMonitor:
    """Get global unified monitor for wallet monitoring"""
    return get_performance_monitor()


def get_unified_monitor() -> UnifiedMonitor:
    """Get global unified monitor"""
    return get_performance_monitor()


def monitor_performance(operation_name: str):
    """Performance measurement decorator"""
    monitor = get_performance_monitor()
    return monitor.measure_operation(operation_name)