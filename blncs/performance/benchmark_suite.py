"""
Advanced Performance Benchmark and Optimization Tools for BLNCS

This module provides comprehensive performance evaluation including:
- CPU, memory, I/O, and concurrency testing
- Detailed performance metrics and analysis
- System optimization recommendations
- Load testing and stress testing capabilities
"""

import time
import threading
import multiprocessing
import psutil
import os
import logging
import statistics
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import gc
import tracemalloc
import memory_profiler
import io
import sys
from contextlib import redirect_stdout, redirect_stderr

logger = logging.getLogger(__name__)

@dataclass
class BenchmarkResult:
    """Benchmark test result."""
    test_name: str
    execution_time: float
    cpu_usage: float
    memory_usage: float
    io_operations: int
    network_io: float
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics."""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_used: float
    memory_available: float
    disk_usage: Dict[str, float]
    network_io: Dict[str, float]
    process_count: int
    thread_count: int
    load_average: Tuple[float, float, float]

class CPUPerformanceTester:
    """CPU performance testing and benchmarking."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.CPUPerformanceTester")

    def test_cpu_intensive_task(self, iterations: int = 1000000) -> BenchmarkResult:
        """Test CPU-intensive operations."""
        start_time = time.time()
        start_cpu = psutil.cpu_percent(interval=None)

        # CPU-intensive computation
        result = 0
        for i in range(iterations):
            result += i * i + i ** 3

        end_time = time.time()
        end_cpu = psutil.cpu_percent(interval=None)

        return BenchmarkResult(
            test_name="cpu_intensive",
            execution_time=end_time - start_time,
            cpu_usage=end_cpu - start_cpu,
            memory_usage=0,  # Will be measured separately
            io_operations=0,
            network_io=0,
            success=True,
            metadata={'iterations': iterations, 'result': result}
        )

    def test_concurrent_cpu_tasks(self, num_threads: int = 4, tasks_per_thread: int = 1000) -> List[BenchmarkResult]:
        """Test CPU performance with concurrent tasks."""
        results = []

        def cpu_task(task_id: int) -> BenchmarkResult:
            start_time = time.time()
            result = sum(i * i for i in range(tasks_per_thread))
            end_time = time.time()

            return BenchmarkResult(
                test_name=f"concurrent_cpu_{task_id}",
                execution_time=end_time - start_time,
                cpu_usage=psutil.cpu_percent(interval=None),
                memory_usage=0,
                io_operations=0,
                network_io=0,
                success=True,
                metadata={'task_id': task_id, 'result': result}
            )

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(cpu_task, i) for i in range(num_threads)]
            results = [future.result() for future in as_completed(futures)]

        return results

class MemoryPerformanceTester:
    """Memory performance testing and profiling."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.MemoryPerformanceTester")

    def test_memory_allocation(self, size_mb: int = 100) -> BenchmarkResult:
        """Test memory allocation and deallocation performance."""
        start_time = time.time()

        # Allocate memory
        data = []
        chunk_size = 1024 * 1024  # 1MB chunks
        num_chunks = size_mb

        for i in range(num_chunks):
            chunk = bytearray(chunk_size)
            data.append(chunk)

        # Measure memory usage
        process = psutil.Process()
        memory_info = process.memory_info()

        # Deallocate
        del data
        gc.collect()

        end_time = time.time()

        return BenchmarkResult(
            test_name="memory_allocation",
            execution_time=end_time - start_time,
            cpu_usage=psutil.cpu_percent(interval=None),
            memory_usage=memory_info.rss / 1024 / 1024,  # MB
            io_operations=0,
            network_io=0,
            success=True,
            metadata={'allocated_mb': size_mb, 'peak_memory_mb': memory_info.rss / 1024 / 1024}
        )

    def profile_memory_usage(self, func: Callable, *args, **kwargs) -> Tuple[Any, Dict[str, Any]]:
        """Profile memory usage of a function."""
        tracemalloc.start()

        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return result, {
            'execution_time': end_time - start_time,
            'current_memory_mb': current / 1024 / 1024,
            'peak_memory_mb': peak / 1024 / 1024
        }

class IOPerformanceTester:
    """I/O performance testing."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.IOPerformanceTester")

    def test_disk_io(self, file_size_mb: int = 100, file_path: str = "/tmp/benchmark_test.bin") -> BenchmarkResult:
        """Test disk I/O performance."""
        start_time = time.time()

        # Write test
        data = os.urandom(file_size_mb * 1024 * 1024)

        with open(file_path, 'wb') as f:
            f.write(data)

        write_time = time.time()

        # Read test
        with open(file_path, 'rb') as f:
            read_data = f.read()

        read_time = time.time()

        # Cleanup
        os.remove(file_path)

        write_duration = write_time - start_time
        read_duration = read_time - write_time

        return BenchmarkResult(
            test_name="disk_io",
            execution_time=read_time - start_time,
            cpu_usage=psutil.cpu_percent(interval=None),
            memory_usage=0,
            io_operations=file_size_mb * 2,  # Read + write
            network_io=0,
            success=True,
            metadata={
                'file_size_mb': file_size_mb,
                'write_duration': write_duration,
                'read_duration': read_duration,
                'write_speed_mbps': (file_size_mb * 8) / write_duration,
                'read_speed_mbps': (file_size_mb * 8) / read_duration
            }
        )

    def test_network_io(self, target_url: str = "https://httpbin.org/get", payload_size: int = 1024) -> BenchmarkResult:
        """Test network I/O performance."""
        import requests

        start_time = time.time()
        bytes_sent = 0
        bytes_received = 0

        try:
            # Test multiple requests
            for i in range(10):
                data = {'data': 'x' * payload_size}
                response = requests.post(target_url, json=data, timeout=10)
                bytes_sent += len(json.dumps(data).encode('utf-8'))
                bytes_received += len(response.content)

            end_time = time.time()

            return BenchmarkResult(
                test_name="network_io",
                execution_time=end_time - start_time,
                cpu_usage=psutil.cpu_percent(interval=None),
                memory_usage=0,
                io_operations=10,  # Number of requests
                network_io=bytes_sent + bytes_received,
                success=True,
                metadata={
                    'requests': 10,
                    'payload_size': payload_size,
                    'bytes_sent': bytes_sent,
                    'bytes_received': bytes_received,
                    'avg_latency': (end_time - start_time) / 10
                }
            )

        except Exception as e:
            return BenchmarkResult(
                test_name="network_io",
                execution_time=time.time() - start_time,
                cpu_usage=psutil.cpu_percent(interval=None),
                memory_usage=0,
                io_operations=0,
                network_io=0,
                success=False,
                error_message=str(e)
            )

class ConcurrencyTester:
    """Concurrency and parallel processing testing."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.ConcurrencyTester")

    def test_threading_performance(self, num_threads: int = 8, tasks_per_thread: int = 100) -> BenchmarkResult:
        """Test threading performance."""
        start_time = time.time()
        results = []

        def thread_task(task_id: int):
            result = sum(i * i for i in range(tasks_per_thread))
            return result

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(thread_task, i) for i in range(num_threads)]
            results = [future.result() for future in as_completed(futures)]

        end_time = time.time()

        return BenchmarkResult(
            test_name="threading_performance",
            execution_time=end_time - start_time,
            cpu_usage=psutil.cpu_percent(interval=None),
            memory_usage=0,
            io_operations=0,
            network_io=0,
            success=True,
            metadata={
                'num_threads': num_threads,
                'tasks_per_thread': tasks_per_thread,
                'total_tasks': num_threads * tasks_per_thread,
                'results_computed': len(results)
            }
        )

    def test_multiprocessing_performance(self, num_processes: int = 4, tasks_per_process: int = 100) -> BenchmarkResult:
        """Test multiprocessing performance."""
        start_time = time.time()
        results = []

        def process_task(task_id: int):
            result = sum(i * i for i in range(tasks_per_process))
            return result

        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            futures = [executor.submit(process_task, i) for i in range(num_processes)]
            results = [future.result() for future in as_completed(futures)]

        end_time = time.time()

        return BenchmarkResult(
            test_name="multiprocessing_performance",
            execution_time=end_time - start_time,
            cpu_usage=psutil.cpu_percent(interval=None),
            memory_usage=0,
            io_operations=0,
            network_io=0,
            success=True,
            metadata={
                'num_processes': num_processes,
                'tasks_per_process': tasks_per_process,
                'total_tasks': num_processes * tasks_per_process,
                'results_computed': len(results)
            }
        )

class SystemPerformanceMonitor:
    """Comprehensive system performance monitoring."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SystemPerformanceMonitor")
        self.metrics_history = []
        self.max_history_size = 1000

    def get_current_metrics(self) -> PerformanceMetrics:
        """Get current system performance metrics."""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk_usage = psutil.disk_usage('/')
        network = psutil.net_io_counters()

        load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)

        metrics = PerformanceMetrics(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_used=memory.used / 1024 / 1024,  # MB
            memory_available=memory.available / 1024 / 1024,  # MB
            disk_usage={'total': disk_usage.total / 1024 / 1024 / 1024,  # GB
                       'used': disk_usage.used / 1024 / 1024 / 1024,
                       'free': disk_usage.free / 1024 / 1024 / 1024,
                       'percent': disk_usage.percent},
            network_io={'bytes_sent': network.bytes_sent,
                       'bytes_recv': network.bytes_recv,
                       'packets_sent': network.packets_sent,
                       'packets_recv': network.packets_recv},
            process_count=len(psutil.pids()),
            thread_count=threading.active_count(),
            load_average=load_avg
        )

        # Store in history
        self.metrics_history.append(metrics)
        if len(self.metrics_history) > self.max_history_size:
            self.metrics_history.pop(0)

        return metrics

    def get_performance_trends(self, duration_minutes: int = 60) -> Dict[str, Any]:
        """Get performance trends over time."""
        cutoff_time = time.time() - (duration_minutes * 60)

        recent_metrics = [
            m for m in self.metrics_history
            if m.timestamp >= cutoff_time
        ]

        if not recent_metrics:
            return {}

        trends = {}

        for attr in ['cpu_percent', 'memory_percent', 'memory_used']:
            values = [getattr(m, attr) for m in recent_metrics]
            trends[f'{attr}_avg'] = statistics.mean(values)
            trends[f'{attr}_max'] = max(values)
            trends[f'{attr}_min'] = min(values)
            trends[f'{attr}_trend'] = self._calculate_trend(values)

        return trends

    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction."""
        if len(values) < 2:
            return 'stable'

        first_half = statistics.mean(values[:len(values)//2])
        second_half = statistics.mean(values[len(values)//2:])

        if second_half > first_half * 1.05:
            return 'increasing'
        elif second_half < first_half * 0.95:
            return 'decreasing'
        else:
            return 'stable'

class PerformanceBenchmarkSuite:
    """Comprehensive performance benchmark suite."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.PerformanceBenchmarkSuite")
        self.cpu_tester = CPUPerformanceTester()
        self.memory_tester = MemoryPerformanceTester()
        self.io_tester = IOPerformanceTester()
        self.concurrency_tester = ConcurrencyTester()
        self.monitor = SystemPerformanceMonitor()

        self.benchmark_results = []
        self.optimization_recommendations = []

    def run_comprehensive_benchmark(self) -> Dict[str, Any]:
        """Run comprehensive performance benchmark."""
        self.logger.info("Starting comprehensive performance benchmark")

        results = {
            'timestamp': time.time(),
            'cpu_tests': [],
            'memory_tests': [],
            'io_tests': [],
            'concurrency_tests': [],
            'system_metrics': {},
            'recommendations': []
        }

        # CPU Tests
        self.logger.info("Running CPU performance tests")
        cpu_results = []

        # Single-threaded CPU test
        cpu_results.append(self.cpu_tester.test_cpu_intensive_task())

        # Multi-threaded CPU test
        cpu_results.extend(self.cpu_tester.test_concurrent_cpu_tasks())

        results['cpu_tests'] = [asdict(r) for r in cpu_results]

        # Memory Tests
        self.logger.info("Running memory performance tests")
        memory_results = []

        # Memory allocation test
        memory_results.append(self.memory_tester.test_memory_allocation())

        results['memory_tests'] = [asdict(r) for r in memory_results]

        # I/O Tests
        self.logger.info("Running I/O performance tests")
        io_results = []

        # Disk I/O test
        try:
            io_results.append(self.io_tester.test_disk_io())
        except Exception as e:
            self.logger.warning(f"Disk I/O test failed: {e}")

        # Network I/O test
        try:
            io_results.append(self.io_tester.test_network_io())
        except Exception as e:
            self.logger.warning(f"Network I/O test failed: {e}")

        results['io_tests'] = [asdict(r) for r in io_results]

        # Concurrency Tests
        self.logger.info("Running concurrency tests")
        concurrency_results = []

        # Threading test
        concurrency_results.append(self.concurrency_tester.test_threading_performance())

        # Multiprocessing test
        try:
            concurrency_results.append(self.concurrency_tester.test_multiprocessing_performance())
        except Exception as e:
            self.logger.warning(f"Multiprocessing test failed: {e}")

        results['concurrency_tests'] = [asdict(r) for r in concurrency_results]

        # System Metrics
        results['system_metrics'] = asdict(self.monitor.get_current_metrics())

        # Generate Recommendations
        results['recommendations'] = self._generate_optimization_recommendations(results)

        # Store results
        self.benchmark_results.append(results)

        self.logger.info("Comprehensive benchmark completed")
        return results

    def _generate_optimization_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate optimization recommendations based on results."""
        recommendations = []

        # CPU recommendations
        cpu_tests = results.get('cpu_tests', [])
        if cpu_tests:
            avg_cpu_time = statistics.mean([r['execution_time'] for r in cpu_tests if r['success']])
            if avg_cpu_time > 5.0:  # More than 5 seconds
                recommendations.append(
                    "High CPU execution time detected. Consider optimizing algorithms or using more efficient data structures."
                )

        # Memory recommendations
        memory_tests = results.get('memory_tests', [])
        if memory_tests:
            for test in memory_tests:
                if test.get('metadata', {}).get('peak_memory_mb', 0) > 1000:  # More than 1GB
                    recommendations.append(
                        "High memory usage detected. Consider implementing memory pooling or optimizing data structures."
                    )

        # I/O recommendations
        io_tests = results.get('io_tests', [])
        for test in io_tests:
            if test.get('metadata', {}).get('write_speed_mbps', 0) < 50:  # Less than 50 MB/s
                recommendations.append(
                    "Low disk I/O performance detected. Consider using SSD storage or optimizing file access patterns."
                )

        # Concurrency recommendations
        concurrency_tests = results.get('concurrency_tests', [])
        for test in concurrency_tests:
            if test.get('metadata', {}).get('num_threads', 0) > 8:
                recommendations.append(
                    "High thread count detected. Monitor for thread contention and consider thread pool optimization."
                )

        return recommendations

    def run_stress_test(self, duration_seconds: int = 300, concurrent_users: int = 10) -> Dict[str, Any]:
        """Run stress test simulation."""
        self.logger.info(f"Starting stress test: {duration_seconds}s, {concurrent_users} users")

        start_time = time.time()
        end_time = start_time + duration_seconds

        stress_results = {
            'start_time': start_time,
            'end_time': end_time,
            'duration': duration_seconds,
            'concurrent_users': concurrent_users,
            'metrics_over_time': [],
            'errors': [],
            'summary': {}
        }

        def simulate_user_activity(user_id: int):
            """Simulate user activity for stress testing."""
            user_start = time.time()

            try:
                while time.time() < end_time:
                    # Simulate various operations
                    time.sleep(0.1)  # Simulate think time

                    # Simulate API calls, computations, etc.
                    result = sum(i * i for i in range(1000))

                    # Simulate I/O operations
                    if user_id % 3 == 0:  # Every 3rd user does I/O
                        pass  # Simulate file operations

            except Exception as e:
                stress_results['errors'].append({
                    'user_id': user_id,
                    'error': str(e),
                    'timestamp': time.time()
                })

        # Start concurrent users
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(simulate_user_activity, i) for i in range(concurrent_users)]

            # Monitor system during test
            while time.time() < end_time:
                metrics = self.monitor.get_current_metrics()
                stress_results['metrics_over_time'].append(asdict(metrics))
                time.sleep(5)  # Sample every 5 seconds

            # Wait for all users to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Stress test user failed: {e}")

        # Generate summary
        if stress_results['metrics_over_time']:
            cpu_values = [m['cpu_percent'] for m in stress_results['metrics_over_time']]
            memory_values = [m['memory_percent'] for m in stress_results['metrics_over_time']]

            stress_results['summary'] = {
                'avg_cpu_percent': statistics.mean(cpu_values),
                'max_cpu_percent': max(cpu_values),
                'avg_memory_percent': statistics.mean(memory_values),
                'max_memory_percent': max(memory_values),
                'total_errors': len(stress_results['errors']),
                'test_completed': time.time() >= end_time
            }

        self.logger.info("Stress test completed")
        return stress_results

    def export_benchmark_report(self, format: str = 'json') -> str:
        """Export benchmark results to specified format."""
        if format.lower() == 'json':
            return json.dumps({
                'benchmark_results': self.benchmark_results,
                'recommendations': self.optimization_recommendations
            }, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")

def create_performance_benchmark_suite() -> PerformanceBenchmarkSuite:
    """Factory function to create performance benchmark suite."""
    return PerformanceBenchmarkSuite()

# Example usage
if __name__ == "__main__":
    # Create benchmark suite
    suite = create_performance_benchmark_suite()

    # Run comprehensive benchmark
    results = suite.run_comprehensive_benchmark()

    # Print results
    print("Performance Benchmark Results:")
    print(f"CPU Tests: {len(results['cpu_tests'])}")
    print(f"Memory Tests: {len(results['memory_tests'])}")
    print(f"I/O Tests: {len(results['io_tests'])}")
    print(f"Concurrency Tests: {len(results['concurrency_tests'])}")

    print(f"\nRecommendations: {len(results['recommendations'])}")
    for rec in results['recommendations']:
        print(f"- {rec}")

    # Export results
    report = suite.export_benchmark_report()
    with open('performance_benchmark_report.json', 'w') as f:
        f.write(report)

    print("Benchmark report exported to performance_benchmark_report.json")
