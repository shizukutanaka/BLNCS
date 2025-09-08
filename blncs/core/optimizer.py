"""
Performance Optimization Module
Automatic performance tuning and optimization for BLNCS.
"""

import time
import threading

# psutil is optional for resource monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from collections import deque
from dataclasses import dataclass

from .logger import get_logger
from .config_manager import get_config_manager
from .fast_cache import get_cache


@dataclass
class PerformanceMetrics:
    """System performance metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    response_time_ms: float
    requests_per_second: float
    cache_hit_rate: float
    error_rate: float


class PerformanceOptimizer:
    """Automatic performance optimization"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.cache = get_cache()
        
        # Optimization settings
        self.enabled = self.config_manager.get('performance.auto_tune', True)
        self.check_interval = 60  # Check every minute
        self.optimization_threshold = 0.8  # Optimize when resource usage > 80%
        
        # Metrics storage
        self.metrics_history = deque(maxlen=1000)
        self.request_times = deque(maxlen=100)
        self.cache_stats = {"hits": 0, "misses": 0}
        self.error_count = 0
        self.request_count = 0
        
        # Optimization state
        self.current_settings = self._get_current_settings()
        self.optimization_lock = threading.Lock()
        self._optimizer_thread = None
        self._stop_optimizer = threading.Event()
        
        # Performance targets
        self.targets = {
            "cpu_percent": 70,
            "memory_percent": 80,
            "response_time_ms": 100,
            "cache_hit_rate": 0.8,
            "error_rate": 0.01
        }
    
    def start(self) -> None:
        """Start performance optimization"""
        if not self.enabled:
            self.logger.info("Performance optimization disabled")
            return
        
        if self._optimizer_thread and self._optimizer_thread.is_alive():
            return
        
        self._stop_optimizer.clear()
        self._optimizer_thread = threading.Thread(target=self._optimization_loop, daemon=True)
        self._optimizer_thread.start()
        self.logger.info("Performance optimizer started")
    
    def stop(self) -> None:
        """Stop performance optimization"""
        self._stop_optimizer.set()
        if self._optimizer_thread:
            self._optimizer_thread.join(timeout=5)
        self.logger.info("Performance optimizer stopped")
    
    def _optimization_loop(self) -> None:
        """Main optimization loop"""
        while not self._stop_optimizer.is_set():
            try:
                # Collect metrics
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Analyze performance
                if self._needs_optimization(metrics):
                    self._optimize_settings(metrics)
                
                # Wait for next check
                self._stop_optimizer.wait(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Optimization error: {e}")
                self._stop_optimizer.wait(30)
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        # System metrics
        if PSUTIL_AVAILABLE:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
        else:
            cpu_percent = 0
            memory_percent = 0
        
        # Application metrics
        avg_response_time = (
            sum(self.request_times) / len(self.request_times) 
            if self.request_times else 0
        )
        
        # Calculate rates
        requests_per_second = self.request_count / 60 if self.request_count > 0 else 0
        cache_total = self.cache_stats["hits"] + self.cache_stats["misses"]
        cache_hit_rate = (
            self.cache_stats["hits"] / cache_total 
            if cache_total > 0 else 0
        )
        error_rate = (
            self.error_count / self.request_count 
            if self.request_count > 0 else 0
        )
        
        # Reset counters
        self.request_count = 0
        self.error_count = 0
        
        return PerformanceMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            response_time_ms=avg_response_time,
            requests_per_second=requests_per_second,
            cache_hit_rate=cache_hit_rate,
            error_rate=error_rate
        )
    
    def _needs_optimization(self, metrics: PerformanceMetrics) -> bool:
        """Check if optimization is needed"""
        # Check against targets
        if metrics.cpu_percent > self.targets["cpu_percent"]:
            self.logger.info(f"High CPU usage: {metrics.cpu_percent:.1f}%")
            return True
        
        if metrics.memory_percent > self.targets["memory_percent"]:
            self.logger.info(f"High memory usage: {metrics.memory_percent:.1f}%")
            return True
        
        if metrics.response_time_ms > self.targets["response_time_ms"]:
            self.logger.info(f"Slow response time: {metrics.response_time_ms:.1f}ms")
            return True
        
        if metrics.cache_hit_rate < self.targets["cache_hit_rate"]:
            self.logger.info(f"Low cache hit rate: {metrics.cache_hit_rate:.2f}")
            return True
        
        if metrics.error_rate > self.targets["error_rate"]:
            self.logger.info(f"High error rate: {metrics.error_rate:.2%}")
            return True
        
        return False
    
    def _optimize_settings(self, metrics: PerformanceMetrics) -> None:
        """Optimize settings based on metrics"""
        with self.optimization_lock:
            optimizations = []
            
            # Optimize cache settings
            if metrics.cache_hit_rate < self.targets["cache_hit_rate"]:
                self._optimize_cache()
                optimizations.append("cache")
            
            # Optimize connection pool
            if metrics.response_time_ms > self.targets["response_time_ms"]:
                self._optimize_connections()
                optimizations.append("connections")
            
            # Optimize resource usage
            if metrics.cpu_percent > self.targets["cpu_percent"]:
                self._optimize_cpu_usage()
                optimizations.append("cpu")
            
            if metrics.memory_percent > self.targets["memory_percent"]:
                self._optimize_memory_usage()
                optimizations.append("memory")
            
            # Optimize error handling
            if metrics.error_rate > self.targets["error_rate"]:
                self._optimize_error_handling()
                optimizations.append("errors")
            
            if optimizations:
                self.logger.info(f"Applied optimizations: {', '.join(optimizations)}")
    
    def _optimize_cache(self) -> None:
        """Optimize cache settings"""
        # Increase cache TTL for better hit rate
        current_ttl = self.config_manager.get('performance.cache_ttl', 300)
        new_ttl = min(current_ttl * 1.5, 1800)  # Max 30 minutes
        self.config_manager.set('performance.cache_ttl', new_ttl)
        
        # Increase cache size
        current_size = self.config_manager.get('performance.cache_max_size', 1000)
        new_size = min(current_size * 1.2, 10000)
        self.config_manager.set('performance.cache_max_size', int(new_size))
        
        self.logger.info(f"Optimized cache: TTL={new_ttl}s, Size={new_size}")
    
    def _optimize_connections(self) -> None:
        """Optimize connection pool settings"""
        # Increase connection pool size
        current_pool = self.config_manager.get('performance.pool_connections', 10)
        new_pool = min(current_pool + 5, 50)
        self.config_manager.set('performance.pool_connections', new_pool)
        
        # Reduce connection timeout for faster failure
        current_timeout = self.config_manager.get('performance.connection_timeout', 5)
        new_timeout = max(current_timeout * 0.8, 1)
        self.config_manager.set('performance.connection_timeout', new_timeout)
        
        self.logger.info(f"Optimized connections: Pool={new_pool}, Timeout={new_timeout}s")
    
    def _optimize_cpu_usage(self) -> None:
        """Optimize CPU usage"""
        # Reduce monitoring frequency
        current_interval = self.config_manager.get('performance.collection_interval', 30)
        new_interval = min(current_interval * 1.5, 300)
        self.config_manager.set('performance.collection_interval', new_interval)
        
        # Reduce parallel requests
        current_parallel = self.config_manager.get('performance.parallel_requests', 10)
        new_parallel = max(current_parallel - 2, 2)
        self.config_manager.set('performance.parallel_requests', new_parallel)
        
        self.logger.info(f"Optimized CPU: Interval={new_interval}s, Parallel={new_parallel}")
    
    def _optimize_memory_usage(self) -> None:
        """Optimize memory usage"""
        # Reduce history size
        current_history = self.config_manager.get('performance.max_history', 10000)
        new_history = max(current_history * 0.5, 100)
        self.config_manager.set('performance.max_history', int(new_history))
        
        # Clear old cache entries
        self.cache.cleanup()
        
        # Trigger garbage collection
        import gc
        gc.collect()
        
        self.logger.info(f"Optimized memory: History={new_history}, Cache cleaned")
    
    def _optimize_error_handling(self) -> None:
        """Optimize error handling"""
        # Increase retry attempts
        current_retries = self.config_manager.get('recovery.max_retries', 3)
        new_retries = min(current_retries + 1, 10)
        self.config_manager.set('recovery.max_retries', new_retries)
        
        # Increase retry delay
        current_delay = self.config_manager.get('recovery.retry_delay', 1.0)
        new_delay = min(current_delay * 1.2, 10)
        self.config_manager.set('recovery.retry_delay', new_delay)
        
        self.logger.info(f"Optimized errors: Retries={new_retries}, Delay={new_delay}s")
    
    def _get_current_settings(self) -> Dict[str, Any]:
        """Get current optimization settings"""
        return {
            "cache_ttl": self.config_manager.get('performance.cache_ttl', 300),
            "cache_size": self.config_manager.get('performance.cache_max_size', 1000),
            "pool_connections": self.config_manager.get('performance.pool_connections', 10),
            "connection_timeout": self.config_manager.get('performance.connection_timeout', 5),
            "parallel_requests": self.config_manager.get('performance.parallel_requests', 10),
            "max_history": self.config_manager.get('performance.max_history', 10000),
            "max_retries": self.config_manager.get('recovery.max_retries', 3),
            "retry_delay": self.config_manager.get('recovery.retry_delay', 1.0)
        }
    
    def record_request(self, response_time_ms: float, error: bool = False) -> None:
        """Record request metrics"""
        self.request_times.append(response_time_ms)
        self.request_count += 1
        if error:
            self.error_count += 1
    
    def record_cache_access(self, hit: bool) -> None:
        """Record cache access"""
        if hit:
            self.cache_stats["hits"] += 1
        else:
            self.cache_stats["misses"] += 1
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance report"""
        if not self.metrics_history:
            return {"status": "No metrics available"}
        
        recent_metrics = list(self.metrics_history)[-10:]
        
        return {
            "current_settings": self.current_settings,
            "average_metrics": {
                "cpu_percent": sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics),
                "memory_percent": sum(m.memory_percent for m in recent_metrics) / len(recent_metrics),
                "response_time_ms": sum(m.response_time_ms for m in recent_metrics) / len(recent_metrics),
                "cache_hit_rate": sum(m.cache_hit_rate for m in recent_metrics) / len(recent_metrics),
                "error_rate": sum(m.error_rate for m in recent_metrics) / len(recent_metrics)
            },
            "optimization_active": self._optimizer_thread.is_alive() if self._optimizer_thread else False,
            "last_check": recent_metrics[-1].timestamp.isoformat() if recent_metrics else None
        }


# Global optimizer instance
_optimizer = None

def get_optimizer() -> PerformanceOptimizer:
    """Get or create global optimizer instance"""
    global _optimizer
    if _optimizer is None:
        _optimizer = PerformanceOptimizer()
    return _optimizer