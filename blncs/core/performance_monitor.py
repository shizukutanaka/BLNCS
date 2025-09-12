"""
Simple Performance Monitor - Wrapper for unified monitoring
This module provides backward compatibility for performance monitoring.
"""

from .monitoring_unified import UnifiedMonitor, MonitoringLevel, AlertSeverity

# Create singleton instance
_monitor_instance = None

def get_performance_monitor(config_manager=None):
    """Get or create performance monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = UnifiedMonitor(config_manager)
        _monitor_instance.set_monitoring_level(MonitoringLevel.STANDARD)
    return _monitor_instance

# Simplified interface for backward compatibility
class SimplePerformanceMonitor:
    """Simple wrapper around unified monitor for performance metrics"""
    
    def __init__(self, config_manager=None):
        self.monitor = get_performance_monitor(config_manager)
        self.monitoring_active = False
    
    def start_monitoring(self):
        """Start performance monitoring"""
        self.monitoring_active = True
        self.monitor.start_monitoring()
        
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring_active = False
        self.monitor.stop_monitoring()
        
    def get_current_metrics(self):
        """Get current performance metrics"""
        return self.monitor.get_current_state()
    
    def check_performance(self):
        """Check current performance and return alerts if any"""
        return self.monitor.get_recent_alerts()

__all__ = ['SimplePerformanceMonitor', 'get_performance_monitor']