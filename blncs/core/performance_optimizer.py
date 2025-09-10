"""
Performance Optimization System for BLNCS
Provides system performance monitoring and optimization with fallback support.
"""

import time
import threading
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
from contextlib import contextmanager
from collections import defaultdict, deque


class PerformanceLevel(Enum):
    """Performance monitoring levels"""
    LOW = 1
    MEDIUM = 2  
    HIGH = 3
    CRITICAL = 4


@dataclass
class OperationProfile:
    """Performance profile for an operation"""
    operation_name: str
    call_count: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    last_execution: Optional[datetime] = None
    
    @property
    def average_time(self) -> float:
        return self.total_time / self.call_count if self.call_count > 0 else 0.0


class PerformanceCache:
    """High-performance caching system"""
    
    def __init__(self, max_size: int = 100, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache = {}
        self._access_times = {}
        self._hit_count = 0
        self._miss_count = 0
        
    def get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        if key in self._cache:
            # Check TTL
            if (datetime.now() - self._access_times[key]).total_seconds() < self.ttl_seconds:
                self._hit_count += 1
                self._access_times[key] = datetime.now()
                return self._cache[key]
            else:
                # Expired, remove it
                del self._cache[key]
                del self._access_times[key]
        
        self._miss_count += 1
        return None
    
    def set(self, key: str, value: Any):
        """Set cached value"""
        # Implement simple LRU if at max size
        if len(self._cache) >= self.max_size and key not in self._cache:
            # Remove oldest accessed item
            oldest_key = min(self._access_times, key=self._access_times.get)
            del self._cache[oldest_key]
            del self._access_times[oldest_key]
        
        self._cache[key] = value
        self._access_times[key] = datetime.now()
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self._hit_count + self._miss_count
        hit_rate = self._hit_count / total_requests if total_requests > 0 else 0.0
        
        return {
            'size': len(self._cache),
            'max_size': self.max_size,
            'hit_count': self._hit_count,
            'miss_count': self._miss_count,
            'hit_rate': hit_rate,
            'ttl_seconds': self.ttl_seconds
        }

# Import enhanced system monitoring with fallback
try:
    from ..utils.system_monitor import (
        get_system_monitor,
        get_current_metrics,
        get_system_health,
        PSUTIL_AVAILABLE
    )
except ImportError:
    PSUTIL_AVAILABLE = False
    
    # Fallback implementations
    def get_current_metrics():
        from ..utils.system_monitor import SystemMetrics
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=0.0, memory_percent=0.0, memory_available_mb=0.0, memory_used_mb=0.0,
            disk_percent=0.0, disk_free_gb=0.0, disk_used_gb=0.0, uptime_seconds=0.0, process_count=0
        )
    
    def get_system_health():
        return {'healthy': True, 'issues': []}
        
    def get_system_monitor():
        return None

from .logger import get_logger
from .config_manager import get_config_manager
from .exceptions import PerformanceError


@dataclass
class OptimizationRecommendation:
    """Performance optimization recommendation"""
    category: str
    priority: str  # high, medium, low
    description: str
    action: str
    estimated_impact: str
    effort_level: str


class PerformanceOptimizer:
    """
    Advanced performance optimization system with fallback support
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config_manager()
        
        # Configuration
        self.enabled = self.config.get('performance.optimization_enabled', True)
        self.monitoring_interval = self.config.get('performance.monitoring_interval', 60)
        
        # Performance tracking
        self.recommendations = []
        self.active_optimizations = {}
        self.operation_profiles = defaultdict(lambda: OperationProfile(''))
        
        # Initialize performance cache
        self.cache = PerformanceCache(
            max_size=self.config.get('performance.cache_size', 100),
            ttl_seconds=self.config.get('performance.cache_ttl', 300)
        )
        
        self.logger.info(f"Performance optimizer initialized (psutil available: {PSUTIL_AVAILABLE})")
    
    @contextmanager
    def measure_operation(self, operation_name: str):
        """Context manager for measuring operation performance"""
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            self._record_operation_profile(operation_name, duration)
    
    def _record_operation_profile(self, operation_name: str, duration: float):
        """Record operation performance metrics"""
        profile = self.operation_profiles[operation_name]
        if not profile.operation_name:
            profile.operation_name = operation_name
        
        profile.call_count += 1
        profile.total_time += duration
        profile.min_time = min(profile.min_time, duration)
        profile.max_time = max(profile.max_time, duration)
        profile.last_execution = datetime.now()
        
        self.logger.debug(f"Operation '{operation_name}' completed in {duration:.4f}s")
    
    def get_operation_profile(self, operation_name: str) -> Optional[OperationProfile]:
        """Get performance profile for an operation"""
        profile = self.operation_profiles.get(operation_name)
        return profile if profile and profile.call_count > 0 else None
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        try:
            # Get current system metrics
            metrics = get_current_metrics()
            
            # Prepare operations summary
            operations_summary = {}
            for op_name, profile in self.operation_profiles.items():
                if profile.call_count > 0:
                    operations_summary[op_name] = {
                        'call_count': profile.call_count,
                        'total_time': profile.total_time,
                        'average_time': profile.average_time,
                        'min_time': profile.min_time,
                        'max_time': profile.max_time,
                        'last_execution': profile.last_execution.isoformat() if profile.last_execution else None
                    }
            
            return {
                'timestamp': datetime.now().isoformat(),
                'system': {
                    'cpu_percent': getattr(metrics, 'cpu_percent', 0.0),
                    'memory_percent': getattr(metrics, 'memory_percent', 0.0),
                    'disk_percent': getattr(metrics, 'disk_percent', 0.0),
                    'psutil_available': PSUTIL_AVAILABLE
                },
                'operations': operations_summary,
                'cache': self.cache.stats(),
                'recommendations': [
                    {
                        'category': r.category,
                        'priority': r.priority,
                        'description': r.description,
                        'action': r.action
                    }
                    for r in self.recommendations[:5]  # Top 5 recommendations
                ],
                'active_optimizations': self.active_optimizations
            }
        except Exception as e:
            self.logger.error(f"Failed to generate performance report: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'system': {},
                'operations': {},
                'cache': self.cache.stats() if self.cache else {},
                'recommendations': []
            }
    
    def validate_performance_optimizer(self) -> Dict[str, Any]:
        """Validate performance optimizer functionality"""
        try:
            # Test system metrics collection
            metrics = get_current_metrics()
            if not metrics:
                raise PerformanceError("Failed to collect system metrics")
            
            # Test health checking
            health = get_system_health()
            if not health:
                raise PerformanceError("Failed to check system health")
            
            return {
                'success': True,
                'metrics_collected': True,
                'health_check_working': True,
                'psutil_available': PSUTIL_AVAILABLE,
                'current_cpu': getattr(metrics, 'cpu_percent', 0.0),
                'current_memory': getattr(metrics, 'memory_percent', 0.0),
                'current_disk': getattr(metrics, 'disk_percent', 0.0)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'psutil_available': PSUTIL_AVAILABLE
            }


# Global performance optimizer instance
_performance_optimizer = None

def get_performance_optimizer() -> PerformanceOptimizer:
    """Get global performance optimizer instance"""
    global _performance_optimizer
    if _performance_optimizer is None:
        _performance_optimizer = PerformanceOptimizer()
    return _performance_optimizer