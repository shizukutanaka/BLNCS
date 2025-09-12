"""
BLNCS Production Monitoring Module
Comprehensive monitoring and alerting system for production environments.
"""

# Core monitoring components
from .production_monitor import ProductionMonitor, MetricsCollector, AlertManager, HealthChecker
from .config import MonitoringConfigManager, MonitoringConfig, MetricThreshold, AlertChannel
from .dashboard import MonitoringDashboard

# Legacy alert management
try:
    from .alert_manager import get_alert_manager
    LEGACY_ALERTS_AVAILABLE = True
except ImportError:
    LEGACY_ALERTS_AVAILABLE = False

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

__all__ = [
    'ProductionMonitor',
    'MetricsCollector', 
    'AlertManager',
    'HealthChecker',
    'MonitoringConfigManager',
    'MonitoringConfig',
    'MetricThreshold',
    'AlertChannel',
    'MonitoringDashboard'
]

if LEGACY_ALERTS_AVAILABLE:
    __all__.append("get_alert_manager")

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

__version__ = '1.0.0'