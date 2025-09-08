"""
BLNCS Unified Monitoring System
Backward compatibility wrapper for enhanced unified monitoring.
"""

from .monitoring_unified import (
    EnhancedUnifiedMonitoring,
    get_unified_monitoring,
    MonitoringLevel,
    AlertSeverity,
    MonitoringAlert,
    SystemSnapshot
)

# Backward compatibility aliases
UnifiedMonitor = EnhancedUnifiedMonitoring
get_monitor = get_unified_monitoring

# Legacy data classes for backward compatibility
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional

@dataclass
class MonitorMetric:
    """Legacy metric data structure for backward compatibility"""
    timestamp: datetime
    metric_type: str
    metric_name: str
    value: Any
    unit: str = ""
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

# Export all public interfaces
__all__ = [
    'UnifiedMonitor',
    'get_monitor', 
    'MonitorMetric',
    'EnhancedUnifiedMonitoring',
    'get_unified_monitoring',
    'MonitoringLevel',
    'AlertSeverity',
    'MonitoringAlert',
    'SystemSnapshot'
]