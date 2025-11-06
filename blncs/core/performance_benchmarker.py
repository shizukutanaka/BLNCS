"""
Performance benchmarking and optimization tools for BLNCS
Implements comprehensive performance testing, profiling, and optimization recommendations
"""

import asyncio
import time
import psutil
import cProfile
import pstats
import io
from typing import Dict, List, Tuple, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import statistics
import logging
import threading
import concurrent.futures
from functools import wraps
import tracemalloc


class BenchmarkType(Enum):
    """Types of performance benchmarks"""
    CPU_INTENSIVE = "cpu_intensive"
    IO_INTENSIVE = "io_intensive"
    MEMORY_INTENSIVE = "memory_intensive"
    NETWORK_INTENSIVE = "network_intensive"
    CONCURRENT_OPERATIONS = "concurrent_operations"
    LATENCY_TEST = "latency_test"
    THROUGHPUT_TEST = "throughput_test"


class OptimizationTarget(Enum):
    """Optimization targets"""
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    IO_LATENCY = "io_latency"
    NETWORK_LATENCY = "network_latency"
    CONCURRENCY = "concurrency"
    THROUGHPUT = "throughput"


@dataclass
class BenchmarkResult:
    """Benchmark test result"""
    test_id: str
    benchmark_type: BenchmarkType
    start_time: float
    end_time: float
    duration: float
    metrics: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None


@dataclass
class PerformanceProfile:
    """Performance profile data"""
    function_name: str
    calls: int
    total_time: float
    per_call_time: float
    cumulative_time: float
    callers: List[str] = field(default_factory=list)


@dataclass
class OptimizationRecommendation:
    """Performance optimization recommendation"""
    target: OptimizationTarget
    severity: str  # low, medium, high, critical
    description: str
    current_value: Any
    recommended_value: Any
    expected_improvement: str
    implementation_effort: str  # low, medium, high


class PerformanceBenchmarker:
    """Comprehensive performance benchmarking and optimization system"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the performance benchmarker

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Benchmark configuration
        self.warmup_iterations = self.config.get('warmup_iterations', 5)
        self.measurement_iterations = self.config.get('measurement_iterations', 10)
        self.max_concurrent_tests = self.config.get('max_concurrent_tests', 3)
        self.benchmark_timeout = self.config.get('benchmark_timeout', 300)  # 5 minutes

        # Performance baselines
        self.baselines = {
            'cpu_usage': 70.0,  # 70% max recommended
            'memory_usage': 80.0,  # 80% max recommended
            'response_time_p95': 200.0,  # 200ms P95
            'throughput': 100.0,  # 100 ops/sec minimum
        }

        # Test results and profiles
        self.benchmark_results: List[BenchmarkResult] = []
        self.performance_profiles: List[PerformanceProfile] = []
        self.system_metrics_history: deque = deque(maxlen=1000)

        # Active profiling
        self.profiling_active = False
        self.profiler = None

        # Memory monitoring
        self.memory_monitoring = False

    def run_comprehensive_benchmark(self) -> Dict[str, Any]:
        """
        Run comprehensive performance benchmark suite

        Returns:
            Comprehensive benchmark results
        """
        self.logger.info("Starting comprehensive performance benchmark")

        results = {}

        # CPU intensive benchmarks
        results['cpu_benchmarks'] = self.run_cpu_benchmarks()

        # Memory benchmarks
        results['memory_benchmarks'] = self.run_memory_benchmarks()

        # I/O benchmarks
        results['io_benchmarks'] = self.run_io_benchmarks()

        # Concurrency benchmarks
        results['concurrency_benchmarks'] = self.run_concurrency_benchmarks()

        # Generate optimization recommendations
        results['optimization_recommendations'] = self.generate_optimization_recommendations(results)

        # System health assessment
        results['system_health'] = self.assess_system_health()

        self.logger.info("Comprehensive benchmark completed")
        return results

    def run_cpu_benchmarks(self) -> List[BenchmarkResult]:
        """Run CPU-intensive performance benchmarks"""
        benchmarks = []

        # Lightning Network routing simulation
        def routing_simulation():
            # Simulate complex routing calculations
            routes = []
            for i in range(1000):
                route = []
                for j in range(10):
                    route.append((i * j) % 100)
                routes.append(route)
            return sum(len(r) for r in routes)

        benchmarks.append(self._run_single_benchmark(
            "lightning_routing_simulation",
            BenchmarkType.CPU_INTENSIVE,
            routing_simulation
        ))

        # Cryptographic operations simulation
        def crypto_simulation():
            import hashlib
            results = []
            for i in range(1000):
                data = f"test_data_{i}".encode()
                results.append(hashlib.sha256(data).hexdigest())
            return len(results)

        benchmarks.append(self._run_single_benchmark(
            "cryptographic_operations",
            BenchmarkType.CPU_INTENSIVE,
            crypto_simulation
        ))

        return benchmarks

    def run_memory_benchmarks(self) -> List[BenchmarkResult]:
        """Run memory-intensive performance benchmarks"""
        benchmarks = []

        # Channel state management simulation
        def channel_state_simulation():
            channels = {}
            for i in range(10000):
                channel_id = f"channel_{i}"
                channels[channel_id] = {
                    'capacity': i * 1000,
                    'local_balance': i * 500,
                    'remote_balance': i * 500,
                    'state': 'active',
                    'transactions': [f"tx_{j}" for j in range(10)]
                }
            return len(channels)

        benchmarks.append(self._run_single_benchmark(
            "channel_state_management",
            BenchmarkType.MEMORY_INTENSIVE,
            channel_state_simulation
        ))

        return benchmarks

    def run_io_benchmarks(self) -> List[BenchmarkResult]:
        """Run I/O intensive performance benchmarks"""
        benchmarks = []

        # Database operations simulation
        def database_simulation():
            # Simulate database operations without actual DB
            operations = []
            for i in range(1000):
                operations.append(f"INSERT INTO transactions VALUES ({i}, 'test')")
            return len(operations)

        benchmarks.append(self._run_single_benchmark(
            "database_operations",
            BenchmarkType.IO_INTENSIVE,
            database_simulation
        ))

        return benchmarks

    def run_concurrency_benchmarks(self) -> List[BenchmarkResult]:
        """Run concurrency performance benchmarks"""
        benchmarks = []

        # Concurrent payment processing simulation
        async def concurrent_payments_simulation():
            async def process_payment(payment_id: int):
                await asyncio.sleep(0.01)  # Simulate processing time
                return f"payment_{payment_id}_processed"

            tasks = [process_payment(i) for i in range(100)]
            results = await asyncio.gather(*tasks)
            return len(results)

        benchmarks.append(self._run_async_benchmark(
            "concurrent_payment_processing",
            BenchmarkType.CONCURRENT_OPERATIONS,
            concurrent_payments_simulation
        ))

        return benchmarks

    def _run_single_benchmark(
        self,
        test_name: str,
        benchmark_type: BenchmarkType,
        test_function: Callable
    ) -> BenchmarkResult:
        """Run a single benchmark test"""
        start_time = time.time()
        success = True
        error_message = None
        metrics = {}

        try:
            # Warmup
            for _ in range(self.warmup_iterations):
                test_function()

            # Measure performance
            execution_times = []
            memory_usage = []

            for _ in range(self.measurement_iterations):
                iteration_start = time.time()

                # Memory monitoring
                if self.memory_monitoring:
                    tracemalloc.start()
                    initial_memory = tracemalloc.get_traced_memory()[0]

                result = test_function()

                if self.memory_monitoring:
                    final_memory = tracemalloc.get_traced_memory()[0]
                    memory_usage.append(final_memory - initial_memory)
                    tracemalloc.stop()

                iteration_end = time.time()
                execution_times.append(iteration_end - iteration_start)

            # Calculate metrics
            metrics = {
                'avg_execution_time': statistics.mean(execution_times),
                'median_execution_time': statistics.median(execution_times),
                'min_execution_time': min(execution_times),
                'max_execution_time': max(execution_times),
                'std_dev_execution_time': statistics.stdev(execution_times) if len(execution_times) > 1 else 0,
                'result': result
            }

            if memory_usage:
                metrics.update({
                    'avg_memory_usage': statistics.mean(memory_usage),
                    'max_memory_usage': max(memory_usage)
                })

        except Exception as e:
            success = False
            error_message = str(e)
            self.logger.error(f"Benchmark {test_name} failed: {e}")

        end_time = time.time()

        result = BenchmarkResult(
            test_id=f"{test_name}_{int(start_time)}",
            benchmark_type=benchmark_type,
            start_time=start_time,
            end_time=end_time,
            duration=end_time - start_time,
            metrics=metrics,
            success=success,
            error_message=error_message
        )

        self.benchmark_results.append(result)
        return result

    async def _run_async_benchmark(
        self,
        test_name: str,
        benchmark_type: BenchmarkType,
        test_function: Callable
    ) -> BenchmarkResult:
        """Run an async benchmark test"""
        start_time = time.time()
        success = True
        error_message = None
        metrics = {}

        try:
            # Warmup
            for _ in range(self.warmup_iterations):
                await test_function()

            # Measure performance
            execution_times = []

            for _ in range(self.measurement_iterations):
                iteration_start = time.time()
                result = await test_function()
                iteration_end = time.time()
                execution_times.append(iteration_end - iteration_start)

            # Calculate metrics
            metrics = {
                'avg_execution_time': statistics.mean(execution_times),
                'median_execution_time': statistics.median(execution_times),
                'min_execution_time': min(execution_times),
                'max_execution_time': max(execution_times),
                'std_dev_execution_time': statistics.stdev(execution_times) if len(execution_times) > 1 else 0,
                'result': result
            }

        except Exception as e:
            success = False
            error_message = str(e)
            self.logger.error(f"Async benchmark {test_name} failed: {e}")

        end_time = time.time()

        result = BenchmarkResult(
            test_id=f"{test_name}_{int(start_time)}",
            benchmark_type=benchmark_type,
            start_time=start_time,
            end_time=end_time,
            duration=end_time - start_time,
            metrics=metrics,
            success=success,
            error_message=error_message
        )

        self.benchmark_results.append(result)
        return result

    def start_profiling(self):
        """Start performance profiling"""
        if self.profiling_active:
            return

        self.profiling_active = True
        self.profiler = cProfile.Profile()
        self.profiler.enable()
        self.logger.info("Performance profiling started")

    def stop_profiling(self) -> List[PerformanceProfile]:
        """Stop profiling and return profile data"""
        if not self.profiling_active or not self.profiler:
            return []

        self.profiler.disable()
        self.profiling_active = False

        # Generate profile stats
        s = io.StringIO()
        ps = pstats.Stats(self.profiler, stream=s).sort_stats('cumulative')
        ps.print_stats()

        # Parse profile data
        profiles = []
        lines = s.getvalue().split('\n')

        for line in lines:
            if line.strip() and not line.startswith(' '):
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        calls = int(parts[0])
                        total_time = float(parts[1])
                        per_call = float(parts[2])
                        cum_time = float(parts[3])
                        function_name = ' '.join(parts[4:])

                        profiles.append(PerformanceProfile(
                            function_name=function_name,
                            calls=calls,
                            total_time=total_time,
                            per_call_time=per_call,
                            cumulative_time=cum_time
                        ))
                    except (ValueError, IndexError):
                        continue

        self.performance_profiles = profiles
        self.logger.info(f"Performance profiling completed, analyzed {len(profiles)} functions")
        return profiles

    def monitor_system_metrics(self):
        """Monitor system performance metrics"""
        while True:
            try:
                metrics = {
                    'timestamp': time.time(),
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                    'network_io': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
                    'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
                }

                self.system_metrics_history.append(metrics)
                time.sleep(10)  # Monitor every 10 seconds

            except Exception as e:
                self.logger.error(f"System monitoring error: {e}")
                time.sleep(10)

    def start_system_monitoring(self):
        """Start system performance monitoring"""
        monitor_thread = threading.Thread(target=self.monitor_system_metrics, daemon=True)
        monitor_thread.start()
        self.logger.info("System performance monitoring started")

    def generate_optimization_recommendations(self, benchmark_results: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Generate performance optimization recommendations"""
        recommendations = []

        # Analyze CPU benchmarks
        cpu_results = benchmark_results.get('cpu_benchmarks', [])
        for result in cpu_results:
            if result.success and result.metrics.get('avg_execution_time', 0) > 1.0:
                recommendations.append(OptimizationRecommendation(
                    target=OptimizationTarget.CPU_USAGE,
                    severity='medium',
                    description=f"High CPU usage in {result.test_id}",
                    current_value='.3f',
                    recommended_value='< 0.5s',
                    expected_improvement='50% faster execution',
                    implementation_effort='medium'
                ))

        # Analyze memory benchmarks
        memory_results = benchmark_results.get('memory_benchmarks', [])
        for result in memory_results:
            if result.success and result.metrics.get('avg_memory_usage', 0) > 1000000:  # 1MB
                recommendations.append(OptimizationRecommendation(
                    target=OptimizationTarget.MEMORY_USAGE,
                    severity='high',
                    description=f"High memory usage in {result.test_id}",
                    current_value=f"{result.metrics['avg_memory_usage'] / 1024:.0f}KB",
                    recommended_value='< 500KB',
                    expected_improvement='60% memory reduction',
                    implementation_effort='high'
                ))

        # Analyze concurrency benchmarks
        concurrency_results = benchmark_results.get('concurrency_benchmarks', [])
        for result in concurrency_results:
            if result.success and result.metrics.get('avg_execution_time', 0) > 0.1:
                recommendations.append(OptimizationRecommendation(
                    target=OptimizationTarget.CONCURRENCY,
                    severity='medium',
                    description=f"Slow concurrent operations in {result.test_id}",
                    current_value='.3f',
                    recommended_value='< 0.05s',
                    expected_improvement='80% faster concurrency',
                    implementation_effort='medium'
                ))

        # System health recommendations
        system_health = benchmark_results.get('system_health', {})
        if system_health.get('cpu_usage', 0) > self.baselines['cpu_usage']:
            recommendations.append(OptimizationRecommendation(
                target=OptimizationTarget.CPU_USAGE,
                severity='high',
                description='High system CPU usage detected',
                current_value='02.1f',
                recommended_value=f"< {self.baselines['cpu_usage']}%",
                expected_improvement='Improve system responsiveness',
                implementation_effort='high'
            ))

        if system_health.get('memory_usage', 0) > self.baselines['memory_usage']:
            recommendations.append(OptimizationRecommendation(
                target=OptimizationTarget.MEMORY_USAGE,
                severity='critical',
                description='High system memory usage detected',
                current_value='02.1f',
                recommended_value=f"< {self.baselines['memory_usage']}%",
                expected_improvement='Prevent memory exhaustion',
                implementation_effort='critical'
            ))

        return recommendations

    def assess_system_health(self) -> Dict[str, Any]:
        """Assess overall system health"""
        if not self.system_metrics_history:
            return {'status': 'no_data'}

        recent_metrics = list(self.system_metrics_history)[-10:]  # Last 10 readings

        cpu_usage = statistics.mean(m['cpu_percent'] for m in recent_metrics)
        memory_usage = statistics.mean(m['memory_percent'] for m in recent_metrics)

        health_score = 100.0

        # Deduct points for high resource usage
        if cpu_usage > 80:
            health_score -= 30
        elif cpu_usage > 60:
            health_score -= 15

        if memory_usage > 85:
            health_score -= 40
        elif memory_usage > 70:
            health_score -= 20

        status = 'excellent' if health_score > 90 else \
                'good' if health_score > 75 else \
                'fair' if health_score > 60 else \
                'poor' if health_score > 40 else 'critical'

        return {
            'status': status,
            'health_score': health_score,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'recommendations_needed': health_score < 80
        }

    def performance_decorator(self, test_name: str = None):
        """Decorator for automatic performance monitoring"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not self.profiling_active:
                    return func(*args, **kwargs)

                start_time = time.time()
                result = func(*args, **kwargs)
                end_time = time.time()

                # Record performance data
                self.logger.debug(
                    f"Performance: {func.__name__} took {end_time - start_time:.4f}s"
                )

                return result
            return wrapper
        return decorator

    def export_benchmark_results(self, format_type: str = 'json') -> str:
        """
        Export benchmark results

        Args:
            format_type: Export format ('json' or 'csv')

        Returns:
            Exported data as string
        """
        if format_type == 'json':
            data = {
                'export_timestamp': time.time(),
                'benchmark_results': [
                    {
                        'test_id': r.test_id,
                        'benchmark_type': r.benchmark_type.value,
                        'duration': r.duration,
                        'metrics': r.metrics,
                        'success': r.success,
                        'error_message': r.error_message
                    }
                    for r in self.benchmark_results
                ],
                'performance_profiles': [
                    {
                        'function_name': p.function_name,
                        'calls': p.calls,
                        'total_time': p.total_time,
                        'per_call_time': p.per_call_time,
                        'cumulative_time': p.cumulative_time
                    }
                    for p in self.performance_profiles
                ]
            }
            return json.dumps(data, indent=2, default=str)

        elif format_type == 'csv':
            lines = ['test_id,benchmark_type,duration,success,avg_execution_time,avg_memory_usage']
            for r in self.benchmark_results:
                if r.success:
                    lines.append(','.join([
                        r.test_id,
                        r.benchmark_type.value,
                        '.3f',
                        str(r.success),
                        '.6f',
                        '.0f'
                    ]))
            return '\n'.join(lines)

        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary statistics"""
        successful_tests = [r for r in self.benchmark_results if r.success]
        failed_tests = [r for r in self.benchmark_results if not r.success]

        summary = {
            'total_tests': len(self.benchmark_results),
            'successful_tests': len(successful_tests),
            'failed_tests': len(failed_tests),
            'success_rate': len(successful_tests) / len(self.benchmark_results) if self.benchmark_results else 0,
            'avg_test_duration': statistics.mean(r.duration for r in self.benchmark_results) if self.benchmark_results else 0,
            'profiling_active': self.profiling_active,
            'profiles_analyzed': len(self.performance_profiles),
            'system_metrics_collected': len(self.system_metrics_history)
        }

        # Add benchmark type breakdown
        type_breakdown = defaultdict(int)
        for result in successful_tests:
            type_breakdown[result.benchmark_type.value] += 1
        summary['benchmark_type_breakdown'] = dict(type_breakdown)

        return summary


# Global performance benchmarker instance
_performance_benchmarker = None

def get_performance_benchmarker() -> PerformanceBenchmarker:
    """Get the global performance benchmarker instance"""
    global _performance_benchmarker
    if _performance_benchmarker is None:
        _performance_benchmarker = PerformanceBenchmarker()
    return _performance_benchmarker
