"""
Network Monitor - Wrapper for unified monitoring
This module provides network-specific monitoring through the unified system.
"""

from .monitoring_unified import UnifiedMonitor, MonitoringLevel

# Create singleton instance
_network_monitor_instance = None

def get_network_monitor(config_manager=None):
    """Get or create network monitor instance"""
    global _network_monitor_instance
    if _network_monitor_instance is None:
        _network_monitor_instance = NetworkMonitor(config_manager)
    return _network_monitor_instance

class NetworkMonitor:
    """Network-specific monitoring wrapper"""
    
    def __init__(self, config_manager=None):
        self.monitor = UnifiedMonitor(config_manager)
        self.monitor.set_monitoring_level(MonitoringLevel.STANDARD)
        
    def monitor_connections(self):
        """Monitor network connections"""
        return self.monitor.monitor_component('network_connections')
        
    def check_network_health(self):
        """Check network health status"""
        state = self.monitor.get_current_state()
        return state.get('network', {})
        
    def get_network_metrics(self):
        """Get network-specific metrics"""
        return self.monitor.get_component_metrics('network')

__all__ = ['NetworkMonitor', 'get_network_monitor']