"""
Alert Manager - Wrapper for monitoring alert system
This module provides backward compatibility for alert management.
"""

from ..monitoring.alert_manager import AlertManager as MonitoringAlertManager

# Create singleton instance
_alert_manager_instance = None

def get_alert_manager(config_manager=None):
    """Get or create alert manager instance"""
    global _alert_manager_instance
    if _alert_manager_instance is None:
        _alert_manager_instance = SimpleAlertManager(config_manager)
    return _alert_manager_instance

# Wrapper class for backward compatibility
class SimpleAlertManager:
    """Simple wrapper around monitoring alert manager"""
    
    def __init__(self, config_manager=None):
        self.alert_manager = MonitoringAlertManager(config_manager)
        
    def send_alert(self, level, message, category=None):
        """Send an alert"""
        return self.alert_manager.send_alert(level, message, category)
        
    def get_recent_alerts(self, limit=10):
        """Get recent alerts"""
        return self.alert_manager.get_recent_alerts(limit)
    
    def clear_alerts(self):
        """Clear all alerts"""
        return self.alert_manager.clear_alerts()

# Re-export main class
AlertManager = MonitoringAlertManager

__all__ = ['SimpleAlertManager', 'AlertManager', 'get_alert_manager']