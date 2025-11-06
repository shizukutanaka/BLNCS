"""
BLNCS Adaptive System Tuner
Lightweight adaptive system tuning based on workload patterns
"""

import time
import threading
from typing import Dict, Any, List, Optional, Callable
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import statistics


@dataclass
class TuningParameter:
    """System tuning parameter"""
    name: str
    current_value: Any
    optimal_value: Any
    value_range: tuple
    last_updated: float
    confidence: float
    source: str  # 'auto', 'manual', 'default'


@dataclass
class WorkloadPattern:
    """Workload pattern analysis"""
    pattern_type: str  # 'cpu_intensive', 'memory_intensive', 'io_intensive', 'mixed'
    confidence: float
    characteristics: Dict[str, float]
    recommended_tuning: Dict[str, Any]
    timestamp: float


class AdaptiveSystemTuner:
    """Lightweight adaptive system tuning system"""

    def __init__(self, tuning_interval: float = 1800.0):  # 30 minutes
        self.tuning_interval = tuning_interval
        self.tuning_parameters: Dict[str, TuningParameter] = {}
        self.workload_history: Dict[str, deque] = defaultdict(deque)
        self.pattern_history: List[WorkloadPattern] = []
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def register_tuning_parameter(self, name: str, current_value: Any,
                                 value_range: tuple, default_value: Any):
        """Register a system tuning parameter"""
        parameter = TuningParameter(
            name=name,
            current_value=current_value,
            optimal_value=current_value,
            value_range=value_range,
            last_updated=time.time(),
            confidence=0.5,
            source='default'
        )

        self.tuning_parameters[name] = parameter

    def _analyze_workload_pattern(self) -> WorkloadPattern:
        """Analyze current workload pattern"""
        # Collect system metrics
        system_metrics = self._collect_system_metrics()

        # Analyze pattern characteristics
        cpu_usage = system_metrics.get('cpu_usage', 0)
        memory_usage = system_metrics.get('memory_usage', 0)
        disk_usage = system_metrics.get('disk_usage', 0)
        network_usage = system_metrics.get('network_usage', 0)

        # Determine pattern type based on resource usage
        if cpu_usage > 80 and memory_usage < 60:
            pattern_type = 'cpu_intensive'
        elif memory_usage > 80 and cpu_usage < 60:
            pattern_type = 'memory_intensive'
        elif disk_usage > 70 or network_usage > 50:
            pattern_type = 'io_intensive'
        else:
            pattern_type = 'mixed'

        # Calculate confidence based on how clearly the pattern emerges
        max_usage = max(cpu_usage, memory_usage, disk_usage, network_usage)
        confidence = min(max_usage / 100.0, 1.0)

        # Generate recommended tuning based on pattern
        recommended_tuning = self._get_tuning_for_pattern(pattern_type, system_metrics)

        return WorkloadPattern(
            pattern_type=pattern_type,
            confidence=confidence,
            characteristics=system_metrics,
            recommended_tuning=recommended_tuning,
            timestamp=time.time()
        )

    def _collect_system_metrics(self) -> Dict[str, float]:
        """Collect comprehensive system metrics"""
        metrics = {}

        try:
            import psutil
            import gc

            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1.0)
            cpu_freq = psutil.cpu_freq()
            metrics['cpu_usage'] = cpu_percent
            metrics['cpu_frequency'] = cpu_freq.current if cpu_freq else 0

            # Memory metrics
            memory = psutil.virtual_memory()
            metrics['memory_usage'] = memory.percent
            metrics['memory_available'] = memory.available / 1024 / 1024  # MB
            metrics['swap_usage'] = psutil.swap_memory().percent if psutil.swap_memory().total > 0 else 0

            # Disk metrics
            disk = psutil.disk_usage('.')
            metrics['disk_usage'] = disk.percent
            metrics['disk_read_rate'] = 0  # Would need more complex monitoring
            metrics['disk_write_rate'] = 0

            # Network metrics
            network = psutil.net_io_counters()
            if network:
                metrics['network_sent_rate'] = network.bytes_sent / 1024 / 1024  # MB/s
                metrics['network_recv_rate'] = network.bytes_recv / 1024 / 1024  # MB/s

            # Process metrics
            metrics['process_count'] = len(psutil.pids())
            metrics['thread_count'] = sum(p.num_threads() for p in psutil.process_iter())

            # GC metrics
            gc_collections = gc.get_count()
            metrics['gc_gen0_collections'] = gc_collections[0]
            metrics['gc_gen1_collections'] = gc_collections[1]
            metrics['gc_gen2_collections'] = gc_collections[2]

        except ImportError:
            # Fallback metrics
            metrics['cpu_usage'] = 50.0
            metrics['memory_usage'] = 60.0
            metrics['disk_usage'] = 70.0
            metrics['thread_count'] = threading.active_count()
            metrics['process_count'] = 100

        return metrics

    def _get_tuning_for_pattern(self, pattern_type: str, metrics: Dict[str, float]) -> Dict[str, Any]:
        """Get tuning recommendations for workload pattern"""
        tuning = {}

        if pattern_type == 'cpu_intensive':
            # For CPU intensive workloads, optimize for CPU throughput
            tuning['thread_pool_size'] = 'increase'
            tuning['memory_cache_size'] = 'decrease'
            tuning['gc_threshold'] = 'increase'
            tuning['cpu_affinity'] = 'optimize'

        elif pattern_type == 'memory_intensive':
            # For memory intensive workloads, optimize memory usage
            tuning['memory_cache_size'] = 'increase'
            tuning['gc_threshold'] = 'decrease'
            tuning['memory_pool_size'] = 'increase'
            tuning['object_cache_ttl'] = 'increase'

        elif pattern_type == 'io_intensive':
            # For I/O intensive workloads, optimize for I/O efficiency
            tuning['disk_cache_size'] = 'increase'
            tuning['network_timeout'] = 'increase'
            tuning['batch_size'] = 'increase'
            tuning['buffer_size'] = 'increase'

        else:  # mixed
            # Balanced tuning for mixed workloads
            tuning['balance_resources'] = 'enable'
            tuning['adaptive_scaling'] = 'enable'
            tuning['mixed_mode_optimization'] = 'enable'

        return tuning

    def apply_tuning_recommendation(self, parameter_name: str, new_value: Any) -> bool:
        """Apply tuning recommendation"""
        with self._lock:
            if parameter_name not in self.tuning_parameters:
                return False

            parameter = self.tuning_parameters[parameter_name]

            # Validate new value is in range
            if isinstance(parameter.value_range, tuple) and len(parameter.value_range) == 2:
                min_val, max_val = parameter.value_range
                if not (min_val <= new_value <= max_val):
                    return False

            # Apply the change
            old_value = parameter.current_value
            parameter.current_value = new_value
            parameter.optimal_value = new_value
            parameter.last_updated = time.time()
            parameter.confidence = 0.8  # High confidence for applied tuning
            parameter.source = 'adaptive'

            # Record the tuning
            tuning_record = {
                'timestamp': time.time(),
                'datetime': datetime.now().isoformat(),
                'parameter': parameter_name,
                'old_value': old_value,
                'new_value': new_value,
                'source': 'adaptive_tuner'
            }

            return True

    def run_tuning_cycle(self) -> Dict[str, Any]:
        """Run one cycle of adaptive tuning"""
        # Analyze workload pattern
        pattern = self._analyze_workload_pattern()

        # Store pattern for historical analysis
        with self._lock:
            self.pattern_history.append(pattern)
            if len(self.pattern_history) > 100:
                self.pattern_history.pop(0)

        # Apply tuning recommendations
        applied_tuning = {}
        for param_name, recommendation in pattern.recommended_tuning.items():
            if param_name in self.tuning_parameters:
                # For now, just record recommendations
                # In a real implementation, this would apply actual system tuning
                applied_tuning[param_name] = {
                    'recommendation': recommendation,
                    'current_value': self.tuning_parameters[param_name].current_value,
                    'applied': False  # Would be True if actually applied
                }

        return {
            'pattern': pattern.__dict__,
            'applied_tuning': applied_tuning,
            'tuning_cycle_completed': True
        }

    def get_tuning_status(self) -> Dict[str, Any]:
        """Get current tuning status"""
        with self._lock:
            parameters = {k: v.__dict__ for k, v in self.tuning_parameters.items()}

            # Get recent patterns
            recent_patterns = self.pattern_history[-5:] if self.pattern_history else []

            return {
                'total_parameters': len(self.tuning_parameters),
                'parameters': parameters,
                'recent_patterns': [p.__dict__ for p in recent_patterns],
                'last_tuning_cycle': self.pattern_history[-1].timestamp if self.pattern_history else None
            }

    def optimize_parameter_range(self, parameter_name: str) -> Dict[str, Any]:
        """Optimize parameter range based on historical performance"""
        with self._lock:
            if parameter_name not in self.tuning_parameters:
                return {'error': 'parameter_not_found'}

            parameter = self.tuning_parameters[parameter_name]

            # Analyze historical performance for this parameter
            # This would require performance correlation data
            # For now, return current status
            return {
                'parameter': parameter_name,
                'current_range': parameter.value_range,
                'optimization_suggestion': 'maintain_current_range',
                'confidence': 0.7
            }

    def start_monitoring(self):
        """Start adaptive tuning monitoring"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop adaptive tuning monitoring"""
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

    def _monitoring_loop(self):
        """Main tuning monitoring loop"""
        while self.monitoring_active:
            try:
                self.run_tuning_cycle()
                time.sleep(self.tuning_interval)
            except Exception:
                time.sleep(self.tuning_interval)

    def _register_default_parameters(self):
        """Register default system tuning parameters"""
        # Memory-related parameters
        self.register_tuning_parameter(
            'gc_threshold',
            current_value=700,
            value_range=(100, 2000),
            default_value=700
        )

        self.register_tuning_parameter(
            'cache_size',
            current_value=1000,
            value_range=(100, 10000),
            default_value=1000
        )

        self.register_tuning_parameter(
            'thread_pool_size',
            current_value=10,
            value_range=(1, 100),
            default_value=10
        )

        self.register_tuning_parameter(
            'connection_pool_size',
            current_value=20,
            value_range=(5, 200),
            default_value=20
        )

        self.register_tuning_parameter(
            'batch_size',
            current_value=100,
            value_range=(10, 1000),
            default_value=100
        )

        self.register_tuning_parameter(
            'timeout_seconds',
            current_value=30,
            value_range=(5, 300),
            default_value=30
        )


class PerformanceCorrelator:
    """Correlate system performance with configuration changes"""

    def __init__(self):
        self.performance_data: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.correlation_matrix: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._lock = threading.Lock()

    def record_performance_sample(self, config_snapshot: Dict[str, Any],
                                 performance_metrics: Dict[str, float]):
        """Record a performance sample with configuration"""
        with self._lock:
            sample = {
                'timestamp': time.time(),
                'datetime': datetime.now().isoformat(),
                'config': config_snapshot.copy(),
                'performance': performance_metrics.copy()
            }

            # Store sample
            for config_key in config_snapshot.keys():
                self.performance_data[config_key].append(sample)

                # Keep only recent samples
                if len(self.performance_data[config_key]) > 200:
                    self.performance_data[config_key].pop(0)

    def calculate_correlations(self) -> Dict[str, Dict[str, float]]:
        """Calculate correlations between config and performance"""
        with self._lock:
            correlations = defaultdict(dict)

            for config_key, samples in self.performance_data.items():
                if len(samples) < 10:
                    continue

                # Extract config values and performance metrics
                config_values = [s['config'][config_key] for s in samples]
                perf_scores = [self._calculate_performance_score(s['performance']) for s in samples]

                if len(set(config_values)) < 2:
                    continue  # Need variation in config values

                try:
                    # Calculate correlation
                    correlation = statistics.correlation(config_values, perf_scores)
                    if not str(correlation) == 'nan':
                        correlations[config_key]['performance_correlation'] = correlation
                except:
                    continue

            self.correlation_matrix = correlations
            return dict(correlations)

    def _calculate_performance_score(self, metrics: Dict[str, float]) -> float:
        """Calculate overall performance score"""
        score = 0.0
        weights = {
            'cpu_usage': -0.3,      # Lower is better
            'memory_usage': -0.2,   # Lower is better
            'response_time': -0.3,  # Lower is better
            'throughput': 0.2       # Higher is better
        }

        for metric, weight in weights.items():
            if metric in metrics:
                score += metrics[metric] * weight

        return score

    def get_optimization_suggestions(self) -> List[Dict[str, Any]]:
        """Get optimization suggestions based on correlations"""
        suggestions = []
        correlations = self.calculate_correlations()

        for config_key, correlation_data in correlations.items():
            correlation = correlation_data.get('performance_correlation', 0)

            if correlation > 0.3:
                suggestions.append({
                    'parameter': config_key,
                    'suggestion': 'increase_value',
                    'reason': f'Positive correlation with performance: {correlation:.3f}',
                    'confidence': abs(correlation)
                })
            elif correlation < -0.3:
                suggestions.append({
                    'parameter': config_key,
                    'suggestion': 'decrease_value',
                    'reason': f'Negative correlation with performance: {correlation:.3f}',
                    'confidence': abs(correlation)
                })

        return suggestions


# Global instances
_adaptive_tuner = None
_performance_correlator = None
_tuner_lock = threading.Lock()


def get_adaptive_tuner() -> AdaptiveSystemTuner:
    """Get global adaptive system tuner"""
    global _adaptive_tuner
    if _adaptive_tuner is None:
        with _tuner_lock:
            if _adaptive_tuner is None:
                _adaptive_tuner = AdaptiveSystemTuner()
                _adaptive_tuner._register_default_parameters()
    return _adaptive_tuner


def get_performance_correlator() -> PerformanceCorrelator:
    """Get global performance correlator"""
    global _performance_correlator
    if _performance_correlator is None:
        with _tuner_lock:
            if _performance_correlator is None:
                _performance_correlator = PerformanceCorrelator()
    return _performance_correlator


def run_tuning_cycle():
    """Run tuning cycle (convenience function)"""
    tuner = get_adaptive_tuner()
    return tuner.run_tuning_cycle()


def get_tuning_status():
    """Get tuning status (convenience function)"""
    tuner = get_adaptive_tuner()
    return tuner.get_tuning_status()


def record_performance_sample(config_snapshot: Dict[str, Any], performance_metrics: Dict[str, float]):
    """Record performance sample (convenience function)"""
    correlator = get_performance_correlator()
    correlator.record_performance_sample(config_snapshot, performance_metrics)


def get_correlation_analysis():
    """Get correlation analysis (convenience function)"""
    correlator = get_performance_correlator()
    return correlator.calculate_correlations()


def get_optimization_suggestions():
    """Get optimization suggestions (convenience function)"""
    correlator = get_performance_correlator()
    return correlator.get_optimization_suggestions()


def start_adaptive_tuning():
    """Start adaptive tuning (convenience function)"""
    tuner = get_adaptive_tuner()
    tuner.start_monitoring()


def stop_adaptive_tuning():
    """Stop adaptive tuning (convenience function)"""
    tuner = get_adaptive_tuner()
    tuner.stop_monitoring()


__all__ = [
    'AdaptiveSystemTuner', 'PerformanceCorrelator', 'TuningParameter', 'WorkloadPattern',
    'get_adaptive_tuner', 'get_performance_correlator', 'run_tuning_cycle',
    'get_tuning_status', 'record_performance_sample', 'get_correlation_analysis',
    'get_optimization_suggestions', 'start_adaptive_tuning', 'stop_adaptive_tuning'
]
