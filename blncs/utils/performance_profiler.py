"""
Performance profiler for BLNCS operations
Provides detailed performance insights and bottleneck identification.
"""

import time
import functools
import threading
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field

from ..core.logger import get_logger


@dataclass
class PerformanceMetric:
    """Performance metric data structure"""
    operation: str
    start_time: float
    end_time: float
    duration: float
    success: bool
    error: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_ms(self) -> float:
        """Get duration in milliseconds"""
        return self.duration * 1000


class PerformanceProfiler:
    """System-wide performance profiler"""
    
    def __init__(self, max_metrics: int = 1000):
        self.logger = get_logger(__name__)
        self.max_metrics = max_metrics
        self._metrics = deque(maxlen=max_metrics)
        self._operation_stats = defaultdict(lambda: {
            'count': 0,
            'total_duration': 0,
            'avg_duration': 0,
            'min_duration': float('inf'),
            'max_duration': 0,
            'success_count': 0,
            'error_count': 0,
            'recent_errors': deque(maxlen=5)
        })
        self._lock = threading.Lock()
        self._enabled = True
    
    def enable(self):
        """Enable profiling"""
        self._enabled = True
        self.logger.info("Performance profiling enabled")
    
    def disable(self):
        """Disable profiling"""
        self._enabled = False
        self.logger.info("Performance profiling disabled")
    
    def is_enabled(self) -> bool:
        """Check if profiling is enabled"""
        return self._enabled
    
    def record_metric(self, metric: PerformanceMetric):
        """Record a performance metric"""
        if not self._enabled:
            return
        
        with self._lock:
            self._metrics.append(metric)
            self._update_operation_stats(metric)
    
    def _update_operation_stats(self, metric: PerformanceMetric):
        """Update operation statistics"""
        stats = self._operation_stats[metric.operation]
        
        stats['count'] += 1
        stats['total_duration'] += metric.duration
        stats['avg_duration'] = stats['total_duration'] / stats['count']
        stats['min_duration'] = min(stats['min_duration'], metric.duration)
        stats['max_duration'] = max(stats['max_duration'], metric.duration)
        
        if metric.success:
            stats['success_count'] += 1
        else:
            stats['error_count'] += 1
            if metric.error:
                stats['recent_errors'].append({
                    'timestamp': datetime.fromtimestamp(metric.end_time),
                    'error': metric.error
                })
    
    def profile_operation(self, operation_name: str, **context):
        """Decorator to profile an operation"""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not self._enabled:
                    return func(*args, **kwargs)
                
                start_time = time.time()
                success = True
                error = None
                
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    success = False
                    error = str(e)
                    raise
                finally:
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    metric = PerformanceMetric(
                        operation=operation_name,
                        start_time=start_time,
                        end_time=end_time,
                        duration=duration,
                        success=success,
                        error=error,
                        context=context
                    )
                    
                    self.record_metric(metric)
            
            return wrapper
        return decorator
    
    def get_operation_stats(self, operation: Optional[str] = None) -> Dict[str, Any]:
        """Get performance statistics for operations"""
        with self._lock:
            if operation:
                return dict(self._operation_stats.get(operation, {}))
            else:
                return {op: dict(stats) for op, stats in self._operation_stats.items()}
    
    def get_slow_operations(self, threshold_ms: float = 1000, limit: int = 10) -> List[Dict[str, Any]]:
        """Get operations that exceed performance threshold"""
        threshold_s = threshold_ms / 1000
        slow_ops = []
        
        with self._lock:
            for operation, stats in self._operation_stats.items():
                if stats['avg_duration'] > threshold_s:
                    slow_ops.append({
                        'operation': operation,
                        'avg_duration_ms': stats['avg_duration'] * 1000,
                        'max_duration_ms': stats['max_duration'] * 1000,
                        'count': stats['count'],
                        'error_rate': stats['error_count'] / stats['count'] if stats['count'] > 0 else 0
                    })
        
        # Sort by average duration (descending)
        slow_ops.sort(key=lambda x: x['avg_duration_ms'], reverse=True)
        return slow_ops[:limit]
    
    def get_error_prone_operations(self, min_error_rate: float = 0.1, limit: int = 10) -> List[Dict[str, Any]]:
        """Get operations with high error rates"""
        error_prone = []
        
        with self._lock:
            for operation, stats in self._operation_stats.items():
                if stats['count'] < 5:  # Skip operations with too few samples
                    continue
                
                error_rate = stats['error_count'] / stats['count']
                if error_rate >= min_error_rate:
                    error_prone.append({
                        'operation': operation,
                        'error_rate': error_rate,
                        'error_count': stats['error_count'],
                        'total_count': stats['count'],
                        'recent_errors': list(stats['recent_errors'])
                    })
        
        # Sort by error rate (descending)
        error_prone.sort(key=lambda x: x['error_rate'], reverse=True)
        return error_prone[:limit]
    
    def get_performance_summary(self, time_window_minutes: int = 60) -> Dict[str, Any]:
        """Get performance summary for recent time window"""
        cutoff_time = time.time() - (time_window_minutes * 60)
        
        recent_metrics = []
        with self._lock:
            for metric in self._metrics:
                if metric.start_time >= cutoff_time:
                    recent_metrics.append(metric)
        
        if not recent_metrics:
            return {
                'time_window_minutes': time_window_minutes,
                'total_operations': 0,
                'avg_duration_ms': 0,
                'success_rate': 0
            }
        
        total_operations = len(recent_metrics)
        successful_operations = sum(1 for m in recent_metrics if m.success)
        total_duration = sum(m.duration for m in recent_metrics)
        avg_duration = total_duration / total_operations
        
        # Group by operation
        operation_counts = defaultdict(int)
        for metric in recent_metrics:
            operation_counts[metric.operation] += 1
        
        return {
            'time_window_minutes': time_window_minutes,
            'total_operations': total_operations,
            'successful_operations': successful_operations,
            'failed_operations': total_operations - successful_operations,
            'success_rate': successful_operations / total_operations,
            'avg_duration_ms': avg_duration * 1000,
            'total_duration_s': total_duration,
            'operations_by_type': dict(operation_counts),
            'operations_per_minute': total_operations / time_window_minutes
        }
    
    def get_recommendations(self) -> List[Dict[str, str]]:
        """Get performance optimization recommendations"""
        recommendations = []
        
        # Check for slow operations
        slow_ops = self.get_slow_operations(threshold_ms=500, limit=5)
        for op in slow_ops:
            recommendations.append({
                'type': 'performance',
                'category': 'slow_operation',
                'operation': op['operation'],
                'message': f"Operation '{op['operation']}' averaging {op['avg_duration_ms']:.1f}ms",
                'suggestion': 'Consider optimization or caching for this operation'
            })
        
        # Check for error-prone operations
        error_prone = self.get_error_prone_operations(min_error_rate=0.2, limit=3)
        for op in error_prone:
            recommendations.append({
                'type': 'reliability',
                'category': 'error_prone',
                'operation': op['operation'],
                'message': f"Operation '{op['operation']}' has {op['error_rate']:.1%} error rate",
                'suggestion': 'Review error handling and add retry logic if appropriate'
            })
        
        # Check overall performance metrics
        summary = self.get_performance_summary(time_window_minutes=30)
        if summary['total_operations'] > 0:
            if summary['success_rate'] < 0.95:
                recommendations.append({
                    'type': 'reliability',
                    'category': 'system_health',
                    'message': f"Overall success rate is {summary['success_rate']:.1%}",
                    'suggestion': 'Investigate system stability and error patterns'
                })
            
            if summary['avg_duration_ms'] > 1000:
                recommendations.append({
                    'type': 'performance',
                    'category': 'system_performance',
                    'message': f"Average operation time is {summary['avg_duration_ms']:.1f}ms",
                    'suggestion': 'Consider system-wide performance optimizations'
                })
        
        return recommendations
    
    def clear_metrics(self):
        """Clear all collected metrics"""
        with self._lock:
            self._metrics.clear()
            self._operation_stats.clear()
        self.logger.info("Performance metrics cleared")
    
    def export_metrics(self, file_path: str, format: str = 'json'):
        """Export performance metrics to file"""
        import json
        
        with self._lock:
            data = {
                'export_timestamp': datetime.now().isoformat(),
                'total_metrics': len(self._metrics),
                'operation_stats': {op: dict(stats) for op, stats in self._operation_stats.items()},
                'performance_summary': self.get_performance_summary(time_window_minutes=1440),  # Last 24 hours
                'slow_operations': self.get_slow_operations(),
                'error_prone_operations': self.get_error_prone_operations(),
                'recommendations': self.get_recommendations()
            }
            
            # Convert deques to lists for JSON serialization
            for op_stats in data['operation_stats'].values():
                if 'recent_errors' in op_stats:
                    op_stats['recent_errors'] = list(op_stats['recent_errors'])
        
        if format.lower() == 'json':
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        self.logger.info(f"Performance metrics exported to {file_path}")


# Context manager for profiling code blocks
class ProfiledOperation:
    """Context manager for profiling operations"""
    
    def __init__(self, profiler: PerformanceProfiler, operation_name: str, **context):
        self.profiler = profiler
        self.operation_name = operation_name
        self.context = context
        self.start_time = None
        self.error = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = time.time()
        duration = end_time - self.start_time
        success = exc_type is None
        error = str(exc_val) if exc_val else None
        
        metric = PerformanceMetric(
            operation=self.operation_name,
            start_time=self.start_time,
            end_time=end_time,
            duration=duration,
            success=success,
            error=error,
            context=self.context
        )
        
        self.profiler.record_metric(metric)


# Global profiler instance
_profiler = None

def get_profiler() -> PerformanceProfiler:
    """Get or create global performance profiler"""
    global _profiler
    if _profiler is None:
        _profiler = PerformanceProfiler()
    return _profiler


def profile(operation_name: str, **context):
    """Decorator for profiling operations"""
    return get_profiler().profile_operation(operation_name, **context)


def profiled_operation(operation_name: str, **context) -> ProfiledOperation:
    """Context manager for profiling operations"""
    return ProfiledOperation(get_profiler(), operation_name, **context)