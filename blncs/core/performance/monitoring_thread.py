"""
Monitoring Thread Module
Handles the unified monitoring thread execution.
"""

import time
import threading
from typing import Optional
import logging


class MonitoringThread:
    """Manages the unified monitoring thread"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.monitor_thread: Optional[threading.Thread] = None
        self.stop_monitoring = threading.Event()
        self.monitor_lock = threading.Lock()
    
    def start_monitoring(self, performance_enabled: bool, wallet_enabled: bool, 
                        performance_interval: int, wallet_interval: int,
                        performance_collector, wallet_monitor, auto_tuner,
                        metrics_history, wallet_history, client=None) -> None:
        """Start the unified monitoring thread"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.logger.warning("Monitoring is already running")
            return
        
        self.stop_monitoring.clear()
        self.monitor_thread = threading.Thread(
            target=self._monitoring_worker,
            args=(performance_enabled, wallet_enabled, performance_interval, 
                  wallet_interval, performance_collector, wallet_monitor, 
                  auto_tuner, metrics_history, wallet_history, client),
            daemon=True
        )
        self.monitor_thread.start()
        
        monitoring_types = []
        if performance_enabled:
            monitoring_types.append("Performance")
        if wallet_enabled and client:
            monitoring_types.append("Wallet")
        
        self.logger.info(f"Started unified monitoring: {', '.join(monitoring_types)}")
    
    def stop_monitoring_thread(self) -> None:
        """Stop the monitoring thread"""
        self.stop_monitoring.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Stopped unified monitoring")
    
    def is_monitoring_active(self) -> bool:
        """Check if monitoring is active"""
        return self.monitor_thread and self.monitor_thread.is_alive()
    
    def _monitoring_worker(self, performance_enabled: bool, wallet_enabled: bool,
                          performance_interval: int, wallet_interval: int,
                          performance_collector, wallet_monitor, auto_tuner,
                          metrics_history, wallet_history, client=None) -> None:
        """Unified monitoring worker thread"""
        performance_last_run = 0
        wallet_last_run = 0
        
        while not self.stop_monitoring.is_set():
            try:
                current_time = time.time()
                
                # Performance monitoring
                if (performance_enabled and 
                    current_time - performance_last_run >= performance_interval):
                    
                    current_metrics = performance_collector.collect_all_metrics()
                    
                    with self.monitor_lock:
                        for metric in current_metrics.values():
                            metrics_history.append(metric)
                            self._check_thresholds(metric)
                    
                    # Auto-tuning
                    auto_tuner.perform_optimization(current_metrics, metrics_history)
                    performance_last_run = current_time
                
                # Wallet monitoring
                if (wallet_enabled and client and 
                    current_time - wallet_last_run >= wallet_interval):
                    
                    wallet_metric = wallet_monitor.check_wallet_status(client)
                    if wallet_metric:
                        with self.monitor_lock:
                            wallet_history.append(wallet_metric)
                        
                        wallet_monitor.check_balance_changes(wallet_metric)
                        wallet_monitor.check_alerts(wallet_metric)
                    
                    wallet_last_run = current_time
                
            except Exception as e:
                self.logger.error(f"Unified monitoring error: {e}")
            
            # Wait for next cycle
            wait_interval = min(performance_interval, wallet_interval) / 10
            self.stop_monitoring.wait(wait_interval)
    
    def _check_thresholds(self, metric) -> None:
        """Check metric thresholds and log alerts"""
        if metric.threshold_critical and metric.value > metric.threshold_critical:
            self.logger.error(f"Performance critical alert: {metric.metric_name}={metric.value}{metric.unit}")
        elif metric.threshold_warning and metric.value > metric.threshold_warning:
            self.logger.warning(f"Performance warning: {metric.metric_name}={metric.value}{metric.unit}")
        
        # Special case for cache hit rate (lower is worse)
        if metric.metric_name == 'cache_hit_rate':
            if metric.threshold_critical and metric.value < metric.threshold_critical:
                self.logger.error(f"Cache hit rate critical: {metric.value:.1%}")
            elif metric.threshold_warning and metric.value < metric.threshold_warning:
                self.logger.warning(f"Cache hit rate warning: {metric.value:.1%}")