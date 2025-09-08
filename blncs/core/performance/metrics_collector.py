"""
Metrics Collection Module
Handles system metrics gathering.
"""

import sys
import os
import time
from datetime import datetime
from typing import Dict, Optional
import logging

from .data_models import PerformanceMetric


class MetricsCollector:
    """Collects system performance metrics"""
    
    def __init__(self, logger: logging.Logger, config, cache):
        self.logger = logger
        self.config = config
        self.cache = cache
        
        self.thresholds = {
            'response_time_ms': {'warning': 1000, 'critical': 5000},
            'memory_usage_mb': {'warning': 100, 'critical': 500},
            'cache_hit_rate': {'warning': 0.7, 'critical': 0.5},
            'disk_usage_mb': {'warning': 1000, 'critical': 5000},
            'connection_count': {'warning': 10, 'critical': 50}
        }
    
    def collect_all_metrics(self) -> Dict[str, PerformanceMetric]:
        """Collect all available system metrics"""
        timestamp = datetime.now()
        metrics = {}
        
        try:
            # Memory usage metric
            memory_metric = self._collect_memory_metric(timestamp)
            if memory_metric:
                metrics[memory_metric.metric_name] = memory_metric
            
            # Cache metrics
            cache_metrics = self._collect_cache_metrics(timestamp)
            metrics.update(cache_metrics)
            
            # Disk usage metric
            disk_metric = self._collect_disk_metric(timestamp)
            if disk_metric:
                metrics[disk_metric.metric_name] = disk_metric
            
            # Response time metric
            response_metric = self._collect_response_time_metric(timestamp)
            if response_metric:
                metrics[response_metric.metric_name] = response_metric
                
        except Exception as e:
            self.logger.error(f"Metrics collection error: {e}")
        
        return metrics
    
    def _collect_memory_metric(self, timestamp: datetime) -> Optional[PerformanceMetric]:
        """Collect memory usage metrics"""
        try:
            memory_mb = sys.getsizeof(self) / 1024 / 1024
            return self._create_metric('memory_usage_mb', memory_mb, 'MB', timestamp)
        except Exception as e:
            self.logger.error(f"Memory metric collection error: {e}")
            return None
    
    def _collect_cache_metrics(self, timestamp: datetime) -> Dict[str, PerformanceMetric]:
        """Collect cache performance metrics"""
        metrics = {}
        
        try:
            cache_stats = self.cache.stats()
            
            hit_rate = cache_stats.get('hit_ratio', 0)
            hit_rate_metric = self._create_metric('cache_hit_rate', hit_rate, 'ratio', timestamp)
            metrics['cache_hit_rate'] = hit_rate_metric
            
            entries_count = cache_stats.get('active_entries', 0)
            entries_metric = self._create_metric('cache_entries', entries_count, 'count', timestamp)
            metrics['cache_entries'] = entries_metric
            
        except Exception as e:
            self.logger.error(f"Cache metrics collection error: {e}")
        
        return metrics
    
    def _collect_disk_metric(self, timestamp: datetime) -> Optional[PerformanceMetric]:
        """Collect disk usage metrics"""
        try:
            data_size = self._get_directory_size('./data')
            disk_mb = data_size / 1024 / 1024
            return self._create_metric('disk_usage_mb', disk_mb, 'MB', timestamp)
        except Exception as e:
            self.logger.error(f"Disk metric collection error: {e}")
            return None
    
    def _collect_response_time_metric(self, timestamp: datetime) -> Optional[PerformanceMetric]:
        """Collect response time metrics"""
        try:
            start_time = time.time()
            _ = self.config.get('system.name')  # Simple operation
            response_time = (time.time() - start_time) * 1000
            return self._create_metric('response_time_ms', response_time, 'ms', timestamp)
        except Exception as e:
            self.logger.error(f"Response time metric collection error: {e}")
            return None
    
    def _create_metric(self, name: str, value: float, unit: str, timestamp: datetime) -> PerformanceMetric:
        """Create a performance metric with thresholds"""
        threshold = self.thresholds.get(name, {})
        
        return PerformanceMetric(
            timestamp=timestamp,
            metric_name=name,
            value=value,
            unit=unit,
            threshold_warning=threshold.get('warning'),
            threshold_critical=threshold.get('critical')
        )
    
    def _get_directory_size(self, directory: str) -> int:
        """Calculate directory size in bytes"""
        total_size = 0
        
        try:
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except OSError:
                        pass
        except Exception:
            pass
            
        return total_size