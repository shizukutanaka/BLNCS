"""
Auto-Tuning Module
Handles automatic performance optimization.
"""

from typing import Dict, List, Callable
import logging

from .data_models import PerformanceMetric


class AutoTuner:
    """Handles automatic performance optimization"""
    
    def __init__(self, logger: logging.Logger, cache):
        self.logger = logger
        self.cache = cache
        self.adjustment_callbacks: List[Callable[[Dict[str, PerformanceMetric]], None]] = []
        self.max_history = 1000
    
    def perform_optimization(self, current_metrics: Dict[str, PerformanceMetric], 
                           metrics_history) -> None:
        """Perform automatic optimization based on metrics"""
        try:
            # Cache optimization
            cache_hit_metric = current_metrics.get('cache_hit_rate')
            if cache_hit_metric and cache_hit_metric.value < 0.6:
                self._optimize_cache()
            
            # Memory optimization
            memory_metric = current_metrics.get('memory_usage_mb')
            if memory_metric and memory_metric.value > 200:
                self._optimize_memory(metrics_history)
            
            # Execute custom callbacks
            self._execute_callbacks(current_metrics)
                
        except Exception as e:
            self.logger.error(f"Auto-tuning error: {e}")
    
    def add_adjustment_callback(self, callback: Callable[[Dict[str, PerformanceMetric]], None]) -> None:
        """Add custom adjustment callback"""
        self.adjustment_callbacks.append(callback)
    
    def _optimize_cache(self) -> None:
        """Optimize cache performance"""
        try:
            expired_count = self.cache.cleanup_expired()
            if expired_count > 0:
                self.logger.info(f"Cache optimization: removed {expired_count} expired entries")
        except Exception as e:
            self.logger.error(f"Cache optimization error: {e}")
    
    def _optimize_memory(self, metrics_history) -> None:
        """Optimize memory usage"""
        try:
            if len(metrics_history) > self.max_history * 0.8:
                # Remove old entries
                while len(metrics_history) > self.max_history // 2:
                    metrics_history.popleft()
                
                self.logger.info("Memory optimization: removed old metrics history")
                
        except Exception as e:
            self.logger.error(f"Memory optimization error: {e}")
    
    def _execute_callbacks(self, current_metrics: Dict[str, PerformanceMetric]) -> None:
        """Execute custom adjustment callbacks"""
        for callback in self.adjustment_callbacks:
            try:
                callback(current_metrics)
            except Exception as e:
                self.logger.error(f"Auto-tuning callback error: {e}")