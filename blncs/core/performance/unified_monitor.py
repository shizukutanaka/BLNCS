"""
Unified Monitor Module
Clean orchestrator for performance and wallet monitoring with reduced complexity.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from collections import deque

from ..logger import get_logger
from ..config import get_config
from ..cache import get_cache
from ..history import record_transaction
from .data_models import PerformanceMetric, WalletMetric
from .metrics_collector import MetricsCollector
from .wallet_monitor import WalletMonitor
from .auto_tuner import AutoTuner
from .monitoring_thread import MonitoringThread


class UnifiedMonitor:
    """Clean unified monitoring system with separated concerns"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.cache = get_cache()
        
        # Configuration
        self.enabled = self.config.get('performance.monitoring_enabled', True)
        self.collection_interval = self.config.get('performance.collection_interval', 30)
        self.max_history = self.config.get('performance.max_history', 1000)
        
        self.wallet_enabled = self.config.get('monitor.enabled', True)
        self.wallet_interval = self.config.get('monitor.interval', 60)
        self.auto_tune = self.config.get('performance.auto_tune', True)
        
        # Data storage
        self.metrics_history = deque(maxlen=self.max_history)
        self.wallet_history = deque(maxlen=self.max_history)
        self.current_metrics = {}
        self.current_wallet = None
        
        # Components
        self.metrics_collector = MetricsCollector(self.logger, self.config, self.cache)
        self.wallet_monitor = WalletMonitor(self.logger, self.config, record_transaction)
        self.auto_tuner = AutoTuner(self.logger, self.cache)
        self.monitoring_thread = MonitoringThread(self.logger)
    
    def start_monitoring(self, client=None) -> None:
        """Start unified monitoring with clean delegation"""
        if not self.enabled and not self.wallet_enabled:
            self.logger.info("All monitoring features disabled")
            return
        
        self.monitoring_thread.start_monitoring(
            self.enabled, self.wallet_enabled,
            self.collection_interval, self.wallet_interval,
            self.metrics_collector, self.wallet_monitor, self.auto_tuner,
            self.metrics_history, self.wallet_history, client
        )
    
    def stop_monitoring(self) -> None:
        """Stop monitoring"""
        self.monitoring_thread.stop_monitoring_thread()
    
    def stop(self) -> None:
        """Alias for stop_monitoring"""
        self.stop_monitoring()
    
    def measure_operation(self, operation_name: str):
        """Operation timing decorator"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    success = True
                except Exception as e:
                    result = e
                    success = False
                finally:
                    duration = (time.time() - start_time) * 1000  # ms
                    
                    # Record operation time
                    metric = PerformanceMetric(
                        timestamp=datetime.now(),
                        metric_name=f'{operation_name}_duration_ms',
                        value=duration,
                        unit='ms'
                    )
                    
                    self.metrics_history.append(metric)
                    self.current_metrics[metric.metric_name] = metric
                    
                    if success:
                        return result
                    else:
                        raise result
            return wrapper
        return decorator
    
    def add_adjustment_callback(self, callback: Callable[[Dict[str, PerformanceMetric]], None]) -> None:
        """Add auto-tuning callback"""
        self.auto_tuner.add_adjustment_callback(callback)
    
    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add wallet alert callback"""
        self.wallet_monitor.add_alert_callback(callback)
    
    def get_performance_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get performance summary for specified time period"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            recent_metrics = [m for m in self.metrics_history if m.timestamp >= cutoff_time]
            
            if not recent_metrics:
                return {'status': 'no_data'}
            
            return self._build_performance_summary(recent_metrics, hours)
            
        except Exception as e:
            self.logger.error(f"Performance summary error: {e}")
            return {'error': str(e)}
    
    def get_wallet_summary(self) -> Dict[str, Any]:
        """Get wallet summary"""
        summary = self.wallet_monitor.get_wallet_summary(list(self.wallet_history))
        summary['monitoring_active'] = self.monitoring_thread.is_monitoring_active()
        return summary
    
    def _build_performance_summary(self, recent_metrics: List[PerformanceMetric], 
                                   hours: int) -> Dict[str, Any]:
        """Build performance summary from metrics"""
        summary = {
            'period_hours': hours,
            'total_samples': len(recent_metrics),
            'monitoring_active': self.monitoring_thread.is_monitoring_active(),
            'auto_tune_enabled': self.auto_tune,
            'metrics': {}
        }
        
        # Group metrics by name
        metric_groups = {}
        for metric in recent_metrics:
            if metric.metric_name not in metric_groups:
                metric_groups[metric.metric_name] = []
            metric_groups[metric.metric_name].append(metric)
        
        # Calculate statistics for each metric
        for metric_name, metrics in metric_groups.items():
            values = [m.value for m in metrics]
            
            if values:
                summary['metrics'][metric_name] = {
                    'current': values[-1],
                    'average': sum(values) / len(values),
                    'min': min(values),
                    'max': max(values),
                    'samples': len(values),
                    'unit': metrics[-1].unit,
                    'threshold_warning': metrics[-1].threshold_warning,
                    'threshold_critical': metrics[-1].threshold_critical
                }
        
        return summary