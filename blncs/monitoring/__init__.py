"""
BLNCS Unified Monitoring Module
Consolidated monitoring system with Lightning Network awareness and real-time alerting.
"""

# Primary unified monitoring system
try:
    from .unified_monitor import (
        UnifiedMonitor,
        MetricsCollector,
        AlertManager,
        HealthMonitor,
        Alert,
        Metric,
        HealthCheck,
        AlertLevel,
        MonitoringEventType,
        get_monitor,
        start_monitoring,
        stop_monitoring,
        get_system_status
    )
    UNIFIED_MONITOR_AVAILABLE = True
except ImportError:
    UNIFIED_MONITOR_AVAILABLE = False

# Legacy monitoring components (for backward compatibility)
try:
    from .production_monitor import ProductionMonitor
    PRODUCTION_MONITOR_AVAILABLE = True

    # Create aliases for backward compatibility
    if UNIFIED_MONITOR_AVAILABLE:
        LegacyProductionMonitor = ProductionMonitor
        ProductionMonitor = UnifiedMonitor

except ImportError:
    PRODUCTION_MONITOR_AVAILABLE = False

try:
    # from .dashboard import MonitoringDashboard  # Skip complex dashboard for now
    DASHBOARD_AVAILABLE = False
except ImportError:
    DASHBOARD_AVAILABLE = False

# Unified dashboard (standalone)
try:
    from .unified_production_dashboard import UnifiedProductionDashboard
    UNIFIED_DASHBOARD_AVAILABLE = True
except ImportError:
    UNIFIED_DASHBOARD_AVAILABLE = False

# Legacy alert management
try:
    from .alert_manager import get_alert_manager as get_legacy_alert_manager
    LEGACY_ALERTS_AVAILABLE = True

    # Create compatibility wrapper
    if UNIFIED_MONITOR_AVAILABLE:
        def get_alert_manager():
            return get_monitor().alert_manager
    else:
        get_alert_manager = get_legacy_alert_manager

except ImportError:
    LEGACY_ALERTS_AVAILABLE = False
    if UNIFIED_MONITOR_AVAILABLE:
        def get_alert_manager():
            return get_monitor().alert_manager

# Conditional prometheus metrics import (might not be available)
try:
    from .prometheus_metrics import (
        PrometheusMetricsCollector,
        MetricDefinition,
        MetricValue,
        MetricType,
        LightningNetworkMetrics,
        SystemMetrics,
        MetricsTimer,
        get_metrics_collector,
        initialize_metrics,
        timed_operation,
        async_timed_operation
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Real-time Lightning monitoring
try:
    from .realtime_lightning import RealtimeLightningMonitor
    REALTIME_LIGHTNING_AVAILABLE = True
except ImportError:
    REALTIME_LIGHTNING_AVAILABLE = False

# Build exports
__all__ = []

# Primary unified system exports
if UNIFIED_MONITOR_AVAILABLE:
    __all__.extend([
        'UnifiedMonitor',
        'MetricsCollector',
        'AlertManager',
        'HealthMonitor',
        'Alert',
        'Metric',
        'HealthCheck',
        'AlertLevel',
        'MonitoringEventType',
        'get_monitor',
        'start_monitoring',
        'stop_monitoring',
        'get_system_status',
        'get_alert_manager'
    ])

# Legacy compatibility exports
if PRODUCTION_MONITOR_AVAILABLE:
    __all__.extend(['ProductionMonitor'])
    if not UNIFIED_MONITOR_AVAILABLE:
        __all__.extend(['HealthChecker'])  # Only if unified not available

if DASHBOARD_AVAILABLE:
    __all__.append('MonitoringDashboard')

if UNIFIED_DASHBOARD_AVAILABLE:
    __all__.append('UnifiedProductionDashboard')

if REALTIME_LIGHTNING_AVAILABLE:
    __all__.append('RealtimeLightningMonitor')

if PROMETHEUS_AVAILABLE:
    __all__.extend([
        "PrometheusMetricsCollector",
        "MetricDefinition",
        "MetricValue",
        "MetricType",
        "LightningNetworkMetrics",
        "SystemMetrics",
        "MetricsTimer",
        "get_metrics_collector",
        "initialize_metrics",
        "timed_operation",
        "async_timed_operation"
    ])

# Convenience functions
def initialize_monitoring(config=None):
    """Initialize and start monitoring system"""
    if UNIFIED_MONITOR_AVAILABLE:
        monitor = get_monitor()
        monitor.start()
        return monitor
    elif PRODUCTION_MONITOR_AVAILABLE:
        return ProductionMonitor()
    else:
        raise ImportError("No monitoring system available")

def get_monitoring_status():
    """Get current monitoring status"""
    if UNIFIED_MONITOR_AVAILABLE:
        return get_system_status()
    else:
        return {"status": "legacy_monitoring", "available": False}

__version__ = '2.0.0'