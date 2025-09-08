"""
Unified Performance Management System
Comprehensive performance monitoring, optimization, and reporting for BLNCS.
"""

import time
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field

from .logger import get_logger
from .config_manager import get_config_manager
from .fast_cache import get_fast_cache
from .connection_pool import get_connection_pool
from .optimizer import get_optimizer
from .liquidity_optimizer import get_liquidity_optimizer
from ..utils.performance_profiler import get_profiler


@dataclass
class PerformanceSnapshot:
    """Comprehensive performance snapshot"""
    timestamp: datetime
    system_metrics: Dict[str, Any] = field(default_factory=dict)
    cache_metrics: Dict[str, Any] = field(default_factory=dict)
    connection_metrics: Dict[str, Any] = field(default_factory=dict)
    profiling_metrics: Dict[str, Any] = field(default_factory=dict)
    liquidity_metrics: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)


class PerformanceManager:
    """Unified performance management system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        
        # Core components
        self.cache = get_fast_cache()
        self.connection_pool = get_connection_pool()
        self.optimizer = get_optimizer()
        self.profiler = get_profiler()
        self.liquidity_optimizer = None  # Initialize lazily when needed
        
        # Performance tracking
        self.snapshots = deque(maxlen=1000)
        self.alerts = deque(maxlen=100)
        
        # Configuration
        self.monitoring_enabled = self.config_manager.get('performance.monitoring_enabled', True)
        self.snapshot_interval = self.config_manager.get('performance.snapshot_interval', 60)
        self.optimization_enabled = self.config_manager.get('performance.auto_optimization', True)
        
        # Threading
        self._monitoring_thread = None
        self._stop_monitoring = threading.Event()
        self._lock = threading.RLock()
        
        # Performance thresholds
        self.thresholds = {
            'memory_usage_critical': self.config_manager.get('performance.memory_critical', 90),
            'cpu_usage_critical': self.config_manager.get('performance.cpu_critical', 85),
            'response_time_critical': self.config_manager.get('performance.response_critical', 2000),  # ms
            'cache_hit_rate_warning': self.config_manager.get('performance.cache_hit_warning', 0.7),
            'error_rate_critical': self.config_manager.get('performance.error_rate_critical', 0.05)
        }
    
    def start(self) -> None:
        """Start performance monitoring"""
        if not self.monitoring_enabled:
            self.logger.info("Performance monitoring disabled")
            return
        
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
        
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitoring_thread.start()
        
        # Start optimizer if enabled
        if self.optimization_enabled:
            self.optimizer.start()
        
        self.logger.info("Performance manager started")
    
    def stop(self) -> None:
        """Stop performance monitoring"""
        self._stop_monitoring.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        
        self.optimizer.stop()
        self.logger.info("Performance manager stopped")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while not self._stop_monitoring.is_set():
            try:
                snapshot = self._collect_performance_snapshot()
                self._analyze_performance(snapshot)
                self._store_snapshot(snapshot)
                
                self._stop_monitoring.wait(self.snapshot_interval)
                
            except Exception as e:
                self.logger.error(f"Performance monitoring error: {e}")
                self._stop_monitoring.wait(30)
    
    def _collect_performance_snapshot(self) -> PerformanceSnapshot:
        """Collect comprehensive performance snapshot"""
        snapshot = PerformanceSnapshot(timestamp=datetime.now())
        
        # System metrics
        snapshot.system_metrics = self._collect_system_metrics()
        
        # Cache metrics
        snapshot.cache_metrics = self.cache.stats()
        
        # Connection pool metrics
        snapshot.connection_metrics = self.connection_pool.get_pool_stats()
        
        # Profiling metrics
        snapshot.profiling_metrics = self._collect_profiling_metrics()
        
        # Liquidity metrics (if Lightning client available)
        if hasattr(self, '_lightning_client') and self._lightning_client:
            if not self.liquidity_optimizer:
                self.liquidity_optimizer = get_liquidity_optimizer(self._lightning_client)
            snapshot.liquidity_metrics = self.liquidity_optimizer.get_liquidity_summary()
        
        return snapshot
    
    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system-level performance metrics"""
        metrics = {}
        
        # Try to get system metrics via psutil if available
        try:
            import psutil
            metrics.update({
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage_percent': psutil.disk_usage('/').percent,
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
                'process_count': len(psutil.pids())
            })
        except ImportError:
            self.logger.debug("psutil not available, using basic metrics")
            metrics.update({
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_usage_percent': 0,
                'load_average': None,
                'process_count': 1
            })
        
        # Add application-specific metrics
        metrics.update({
            'threads_active': threading.active_count(),
            'cache_size': len(self.cache._cache),
            'profiler_enabled': self.profiler.is_enabled(),
            'optimizer_active': hasattr(self.optimizer, '_optimizer_thread') and 
                              self.optimizer._optimizer_thread and 
                              self.optimizer._optimizer_thread.is_alive()
        })
        
        return metrics
    
    def _collect_profiling_metrics(self) -> Dict[str, Any]:
        """Collect performance profiling metrics"""
        if not self.profiler.is_enabled():
            return {'enabled': False}
        
        metrics = {
            'enabled': True,
            'slow_operations': self.profiler.get_slow_operations(threshold_ms=500, limit=5),
            'error_prone_operations': self.profiler.get_error_prone_operations(min_error_rate=0.1, limit=5),
            'performance_summary': self.profiler.get_performance_summary(time_window_minutes=15),
            'recommendations': self.profiler.get_recommendations()
        }
        
        return metrics
    
    def _analyze_performance(self, snapshot: PerformanceSnapshot) -> None:
        """Analyze performance snapshot and generate alerts/recommendations"""
        alerts = []
        recommendations = []
        
        # Check system metrics against thresholds
        sys_metrics = snapshot.system_metrics
        
        if sys_metrics.get('memory_percent', 0) > self.thresholds['memory_usage_critical']:
            alerts.append({
                'type': 'critical',
                'category': 'memory',
                'message': f"High memory usage: {sys_metrics['memory_percent']:.1f}%",
                'threshold': self.thresholds['memory_usage_critical'],
                'timestamp': snapshot.timestamp
            })
            recommendations.append({
                'type': 'immediate',
                'action': 'optimize_memory',
                'description': 'Trigger memory optimization to free resources',
                'priority': 'high'
            })
        
        if sys_metrics.get('cpu_percent', 0) > self.thresholds['cpu_usage_critical']:
            alerts.append({
                'type': 'critical',
                'category': 'cpu',
                'message': f"High CPU usage: {sys_metrics['cpu_percent']:.1f}%",
                'threshold': self.thresholds['cpu_usage_critical'],
                'timestamp': snapshot.timestamp
            })
            recommendations.append({
                'type': 'immediate',
                'action': 'reduce_cpu_load',
                'description': 'Reduce monitoring frequency and parallel operations',
                'priority': 'high'
            })
        
        # Check cache performance
        cache_metrics = snapshot.cache_metrics
        if cache_metrics.get('hit_rate', 1.0) < self.thresholds['cache_hit_rate_warning']:
            alerts.append({
                'type': 'warning',
                'category': 'cache',
                'message': f"Low cache hit rate: {cache_metrics['hit_rate']:.2%}",
                'threshold': self.thresholds['cache_hit_rate_warning'],
                'timestamp': snapshot.timestamp
            })
            recommendations.append({
                'type': 'optimization',
                'action': 'optimize_cache',
                'description': 'Increase cache size or TTL to improve hit rate',
                'priority': 'medium'
            })
        
        # Check connection pool performance
        conn_metrics = snapshot.connection_metrics
        if conn_metrics.get('success_rate', 1.0) < 0.95:
            alerts.append({
                'type': 'warning',
                'category': 'connections',
                'message': f"Low connection success rate: {conn_metrics.get('success_rate', 0):.2%}",
                'threshold': 0.95,
                'timestamp': snapshot.timestamp
            })
            recommendations.append({
                'type': 'optimization',
                'action': 'optimize_connections',
                'description': 'Increase connection pool size or timeout settings',
                'priority': 'medium'
            })
        
        # Check profiling data for performance issues
        profiling = snapshot.profiling_metrics
        if profiling.get('enabled') and profiling.get('slow_operations'):
            slow_ops = profiling['slow_operations']
            if slow_ops:
                alerts.append({
                    'type': 'warning',
                    'category': 'performance',
                    'message': f"{len(slow_ops)} operations are running slowly",
                    'details': slow_ops[:3],  # First 3 slow operations
                    'timestamp': snapshot.timestamp
                })
                recommendations.extend([
                    {
                        'type': 'investigation',
                        'action': 'analyze_slow_operation',
                        'description': f"Investigate slow operation: {op['operation']}",
                        'priority': 'medium',
                        'details': op
                    } for op in slow_ops[:2]  # Top 2 slow operations
                ])
        
        # Store alerts and recommendations
        snapshot.recommendations = recommendations
        
        with self._lock:
            self.alerts.extend(alerts)
    
    def _store_snapshot(self, snapshot: PerformanceSnapshot) -> None:
        """Store performance snapshot"""
        with self._lock:
            self.snapshots.append(snapshot)
    
    def get_current_performance(self) -> Dict[str, Any]:
        """Get current performance status"""
        if not self.snapshots:
            return {'status': 'no_data'}
        
        latest = self.snapshots[-1]
        
        return {
            'timestamp': latest.timestamp.isoformat(),
            'system': latest.system_metrics,
            'cache': latest.cache_metrics,
            'connections': latest.connection_metrics,
            'profiling': latest.profiling_metrics.get('performance_summary', {}),
            'liquidity': latest.liquidity_metrics,
            'recommendations': latest.recommendations,
            'monitoring_active': self._monitoring_thread.is_alive() if self._monitoring_thread else False
        }
    
    def get_performance_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive performance report for specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Filter snapshots within time period
        recent_snapshots = [
            s for s in self.snapshots 
            if s.timestamp >= cutoff_time
        ]
        
        if not recent_snapshots:
            return {'status': 'no_data', 'hours': hours}
        
        # Calculate aggregated metrics
        report = {
            'time_period_hours': hours,
            'snapshots_count': len(recent_snapshots),
            'first_snapshot': recent_snapshots[0].timestamp.isoformat(),
            'last_snapshot': recent_snapshots[-1].timestamp.isoformat(),
            'system_performance': self._aggregate_system_metrics(recent_snapshots),
            'cache_performance': self._aggregate_cache_metrics(recent_snapshots),
            'connection_performance': self._aggregate_connection_metrics(recent_snapshots),
            'performance_trends': self._calculate_performance_trends(recent_snapshots),
            'alerts_summary': self._get_alerts_summary(cutoff_time),
            'recommendations': self._get_consolidated_recommendations(recent_snapshots)
        }
        
        return report
    
    def _aggregate_system_metrics(self, snapshots: List[PerformanceSnapshot]) -> Dict[str, Any]:
        """Aggregate system metrics across snapshots"""
        cpu_values = [s.system_metrics.get('cpu_percent', 0) for s in snapshots]
        memory_values = [s.system_metrics.get('memory_percent', 0) for s in snapshots]
        
        return {
            'cpu_usage': {
                'avg': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
                'max': max(cpu_values) if cpu_values else 0,
                'min': min(cpu_values) if cpu_values else 0
            },
            'memory_usage': {
                'avg': sum(memory_values) / len(memory_values) if memory_values else 0,
                'max': max(memory_values) if memory_values else 0,
                'min': min(memory_values) if memory_values else 0
            },
            'avg_threads': sum(s.system_metrics.get('threads_active', 1) for s in snapshots) / len(snapshots),
            'optimizer_uptime': sum(1 for s in snapshots if s.system_metrics.get('optimizer_active')) / len(snapshots)
        }
    
    def _aggregate_cache_metrics(self, snapshots: List[PerformanceSnapshot]) -> Dict[str, Any]:
        """Aggregate cache metrics across snapshots"""
        hit_rates = [s.cache_metrics.get('hit_rate', 1.0) for s in snapshots]
        cache_sizes = [s.cache_metrics.get('size', 0) for s in snapshots]
        
        return {
            'hit_rate': {
                'avg': sum(hit_rates) / len(hit_rates) if hit_rates else 1.0,
                'min': min(hit_rates) if hit_rates else 1.0
            },
            'avg_size': sum(cache_sizes) / len(cache_sizes) if cache_sizes else 0,
            'max_size': max(cache_sizes) if cache_sizes else 0,
            'efficiency': 'excellent' if (sum(hit_rates) / len(hit_rates) if hit_rates else 1.0) > 0.8 else 'good' if (sum(hit_rates) / len(hit_rates) if hit_rates else 1.0) > 0.6 else 'poor'
        }
    
    def _aggregate_connection_metrics(self, snapshots: List[PerformanceSnapshot]) -> Dict[str, Any]:
        """Aggregate connection metrics across snapshots"""
        success_rates = [s.connection_metrics.get('success_rate', 1.0) for s in snapshots]
        avg_latencies = [s.connection_metrics.get('avg_latency_ms', 0) for s in snapshots]
        
        return {
            'success_rate': {
                'avg': sum(success_rates) / len(success_rates) if success_rates else 1.0,
                'min': min(success_rates) if success_rates else 1.0
            },
            'latency': {
                'avg': sum(avg_latencies) / len(avg_latencies) if avg_latencies else 0,
                'max': max(avg_latencies) if avg_latencies else 0
            },
            'reliability': 'excellent' if (sum(success_rates) / len(success_rates) if success_rates else 1.0) > 0.98 else 'good' if (sum(success_rates) / len(success_rates) if success_rates else 1.0) > 0.95 else 'poor'
        }
    
    def _calculate_performance_trends(self, snapshots: List[PerformanceSnapshot]) -> Dict[str, Any]:
        """Calculate performance trends over time"""
        if len(snapshots) < 2:
            return {'insufficient_data': True}
        
        # Calculate trends for key metrics
        first_half = snapshots[:len(snapshots)//2]
        second_half = snapshots[len(snapshots)//2:]
        
        def avg_metric(snapshot_list, metric_path):
            values = []
            for s in snapshot_list:
                if '.' in metric_path:
                    category, metric = metric_path.split('.', 1)
                    if category == 'system':
                        values.append(s.system_metrics.get(metric, 0))
                    elif category == 'cache':
                        values.append(s.cache_metrics.get(metric, 0))
                    elif category == 'connections':
                        values.append(s.connection_metrics.get(metric, 0))
            return sum(values) / len(values) if values else 0
        
        trends = {}
        for metric in ['system.cpu_percent', 'system.memory_percent', 'cache.hit_rate', 'connections.success_rate']:
            first_avg = avg_metric(first_half, metric)
            second_avg = avg_metric(second_half, metric)
            
            if first_avg > 0:
                change_percent = ((second_avg - first_avg) / first_avg) * 100
                trends[metric] = {
                    'change_percent': change_percent,
                    'direction': 'improving' if change_percent > 5 else 'declining' if change_percent < -5 else 'stable',
                    'first_period_avg': first_avg,
                    'second_period_avg': second_avg
                }
        
        return trends
    
    def _get_alerts_summary(self, cutoff_time: datetime) -> Dict[str, Any]:
        """Get summary of alerts within time period"""
        recent_alerts = [a for a in self.alerts if a['timestamp'] >= cutoff_time]
        
        if not recent_alerts:
            return {'total': 0, 'by_type': {}, 'by_category': {}}
        
        by_type = defaultdict(int)
        by_category = defaultdict(int)
        
        for alert in recent_alerts:
            by_type[alert['type']] += 1
            by_category[alert['category']] += 1
        
        return {
            'total': len(recent_alerts),
            'by_type': dict(by_type),
            'by_category': dict(by_category),
            'latest': recent_alerts[-5:]  # Last 5 alerts
        }
    
    def _get_consolidated_recommendations(self, snapshots: List[PerformanceSnapshot]) -> List[Dict[str, Any]]:
        """Get consolidated recommendations from recent snapshots"""
        all_recommendations = []
        for snapshot in snapshots:
            all_recommendations.extend(snapshot.recommendations)
        
        # Group similar recommendations
        recommendation_groups = defaultdict(list)
        for rec in all_recommendations:
            key = rec.get('action', 'unknown')
            recommendation_groups[key].append(rec)
        
        # Return most frequent recommendations
        consolidated = []
        for action, recs in recommendation_groups.items():
            if len(recs) >= 3:  # Only show recommendations that appear multiple times
                consolidated.append({
                    'action': action,
                    'frequency': len(recs),
                    'priority': recs[-1].get('priority', 'medium'),
                    'description': recs[-1].get('description', ''),
                    'last_seen': max(rec.get('timestamp', datetime.min) for rec in recs if 'timestamp' in rec)
                })
        
        # Sort by frequency and priority
        priority_order = {'high': 3, 'medium': 2, 'low': 1}
        consolidated.sort(key=lambda x: (priority_order.get(x['priority'], 0), x['frequency']), reverse=True)
        
        return consolidated[:10]  # Top 10 recommendations
    
    def optimize_performance(self, target_areas: Optional[List[str]] = None) -> Dict[str, Any]:
        """Trigger immediate performance optimization"""
        if not target_areas:
            target_areas = ['cache', 'connections', 'memory']
        
        results = {}
        
        if 'cache' in target_areas:
            # Clear expired cache entries
            expired_count = self.cache.cleanup_expired()
            results['cache'] = {
                'action': 'cleanup_expired',
                'expired_entries_removed': expired_count,
                'current_size': len(self.cache._cache)
            }
        
        if 'connections' in target_areas:
            # Cleanup idle connections
            self.connection_pool.cleanup_idle_connections()
            stats = self.connection_pool.get_pool_stats()
            results['connections'] = {
                'action': 'cleanup_idle',
                'active_connections': stats['active_connections'],
                'total_connections': stats['total_connections']
            }
        
        if 'memory' in target_areas:
            # Trigger garbage collection
            import gc
            collected = gc.collect()
            results['memory'] = {
                'action': 'garbage_collection',
                'objects_collected': collected
            }
        
        self.logger.info(f"Performance optimization completed: {results}")
        return results
    
    def set_lightning_client(self, client) -> None:
        """Set Lightning client for liquidity monitoring"""
        self._lightning_client = client
        if client:
            self.liquidity_optimizer = get_liquidity_optimizer(client)
            self.logger.info("Lightning client set for performance monitoring")


# Global performance manager instance
_performance_manager = None

def get_performance_manager() -> PerformanceManager:
    """Get or create global performance manager instance"""
    global _performance_manager
    if _performance_manager is None:
        _performance_manager = PerformanceManager()
    return _performance_manager