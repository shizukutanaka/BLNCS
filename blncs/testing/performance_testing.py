"""
Simple Performance Testing and Benchmarking
Lightweight performance testing tools for BLNCS components.
"""

import time
import threading
import statistics
import concurrent.futures
from typing import Dict, List, Any, Callable, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json

from ..core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class PerformanceResult:
    """Performance test result."""
    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    duration_seconds: float
    requests_per_second: float
    avg_response_time_ms: float
    min_response_time_ms: float
    max_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    error_rate_percent: float
    errors: List[str] = field(default_factory=list)

@dataclass
class LoadTestConfig:
    """Load test configuration."""
    name: str
    target_function: Callable
    num_requests: int = 100
    concurrent_users: int = 10
    duration_seconds: Optional[int] = None
    ramp_up_time: int = 0
    think_time: float = 0.0
    timeout_seconds: int = 30

class PerformanceTester:
    """Simple performance testing framework."""
    
    def __init__(self):
        """Initialize performance tester."""
        self.logger = get_logger(__name__)
        self.results_history: List[PerformanceResult] = []
    
    def benchmark_function(self, func: Callable, iterations: int = 1000, 
                          warmup_iterations: int = 100, name: str = None) -> PerformanceResult:
        """Benchmark a single function."""
        test_name = name or func.__name__
        self.logger.info(f"Starting benchmark: {test_name}")
        
        # Warmup runs
        for _ in range(warmup_iterations):
            try:
                func()
            except Exception:
                pass  # Ignore warmup errors
        
        # Actual benchmark
        response_times = []
        successful = 0
        errors = []
        
        start_time = time.time()
        
        for i in range(iterations):
            request_start = time.time()
            try:
                func()
                request_end = time.time()
                response_times.append((request_end - request_start) * 1000)  # Convert to ms
                successful += 1
            except Exception as e:
                errors.append(f"Request {i+1}: {str(e)}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Calculate statistics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
            p95_response_time = self._percentile(response_times, 95)
            p99_response_time = self._percentile(response_times, 99)
        else:
            avg_response_time = min_response_time = max_response_time = 0
            p95_response_time = p99_response_time = 0
        
        failed = len(errors)
        error_rate = (failed / iterations) * 100 if iterations > 0 else 0
        rps = successful / duration if duration > 0 else 0
        
        result = PerformanceResult(
            test_name=test_name,
            total_requests=iterations,
            successful_requests=successful,
            failed_requests=failed,
            duration_seconds=duration,
            requests_per_second=rps,
            avg_response_time_ms=avg_response_time,
            min_response_time_ms=min_response_time,
            max_response_time_ms=max_response_time,
            p95_response_time_ms=p95_response_time,
            p99_response_time_ms=p99_response_time,
            error_rate_percent=error_rate,
            errors=errors[:10]  # Keep first 10 errors
        )
        
        self.results_history.append(result)
        self.logger.info(f"Benchmark completed: {test_name} - {rps:.2f} RPS")
        return result
    
    def load_test(self, config: LoadTestConfig) -> PerformanceResult:
        """Run a load test with concurrent users."""
        self.logger.info(f"Starting load test: {config.name}")
        
        response_times = []
        successful = 0
        errors = []
        
        def worker(worker_id: int, start_barrier: threading.Barrier):
            """Worker function for load testing."""
            nonlocal successful, errors, response_times
            
            # Wait for all workers to be ready
            start_barrier.wait()
            
            worker_start = time.time()
            worker_requests = 0
            
            while True:
                # Check if duration-based test is complete
                if config.duration_seconds and (time.time() - worker_start) >= config.duration_seconds:
                    break
                
                # Check if request-based test is complete
                if not config.duration_seconds and worker_requests >= (config.num_requests // config.concurrent_users):
                    break
                
                request_start = time.time()
                try:
                    config.target_function()
                    request_end = time.time()
                    
                    with threading.Lock():
                        response_times.append((request_end - request_start) * 1000)
                        successful += 1
                        
                except Exception as e:
                    with threading.Lock():
                        errors.append(f"Worker {worker_id}: {str(e)}")
                
                worker_requests += 1
                
                # Think time between requests
                if config.think_time > 0:
                    time.sleep(config.think_time)
        
        # Start load test
        start_barrier = threading.Barrier(config.concurrent_users)
        test_start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.concurrent_users) as executor:
            # Submit worker tasks
            futures = []
            for i in range(config.concurrent_users):
                future = executor.submit(worker, i, start_barrier)
                futures.append(future)
                
                # Ramp up delay
                if config.ramp_up_time > 0:
                    time.sleep(config.ramp_up_time / config.concurrent_users)
            
            # Wait for all workers to complete
            concurrent.futures.wait(futures, timeout=config.timeout_seconds + 10)
        
        test_end_time = time.time()
        duration = test_end_time - test_start_time
        
        # Calculate statistics
        total_requests = successful + len(errors)
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
            p95_response_time = self._percentile(response_times, 95)
            p99_response_time = self._percentile(response_times, 99)
        else:
            avg_response_time = min_response_time = max_response_time = 0
            p95_response_time = p99_response_time = 0
        
        error_rate = (len(errors) / total_requests) * 100 if total_requests > 0 else 0
        rps = successful / duration if duration > 0 else 0
        
        result = PerformanceResult(
            test_name=config.name,
            total_requests=total_requests,
            successful_requests=successful,
            failed_requests=len(errors),
            duration_seconds=duration,
            requests_per_second=rps,
            avg_response_time_ms=avg_response_time,
            min_response_time_ms=min_response_time,
            max_response_time_ms=max_response_time,
            p95_response_time_ms=p95_response_time,
            p99_response_time_ms=p99_response_time,
            error_rate_percent=error_rate,
            errors=errors[:10]  # Keep first 10 errors
        )
        
        self.results_history.append(result)
        self.logger.info(f"Load test completed: {config.name} - {rps:.2f} RPS, {error_rate:.2f}% errors")
        return result
    
    def stress_test(self, func: Callable, max_users: int = 100, 
                   step_size: int = 10, step_duration: int = 30,
                   name: str = None) -> List[PerformanceResult]:
        """Run a stress test with increasing load."""
        test_name = name or f"{func.__name__}_stress_test"
        self.logger.info(f"Starting stress test: {test_name}")
        
        results = []
        
        for users in range(step_size, max_users + 1, step_size):
            config = LoadTestConfig(
                name=f"{test_name}_users_{users}",
                target_function=func,
                concurrent_users=users,
                duration_seconds=step_duration
            )
            
            result = self.load_test(config)
            results.append(result)
            
            # Log progress
            self.logger.info(
                f"Stress test step: {users} users - "
                f"{result.requests_per_second:.2f} RPS, "
                f"{result.error_rate_percent:.2f}% errors"
            )
            
            # Break if error rate is too high
            if result.error_rate_percent > 50:
                self.logger.warning("High error rate detected, stopping stress test")
                break
        
        return results
    
    def benchmark_suite(self, functions: Dict[str, Callable], iterations: int = 100) -> Dict[str, PerformanceResult]:
        """Benchmark multiple functions."""
        results = {}
        
        for name, func in functions.items():
            result = self.benchmark_function(func, iterations=iterations, name=name)
            results[name] = result
        
        return results
    
    def memory_benchmark(self, func: Callable, iterations: int = 100, name: str = None) -> Dict[str, Any]:
        """Benchmark memory usage of a function."""
        test_name = name or func.__name__
        
        try:
            import tracemalloc
            import psutil
            import os
            
            # Get initial memory
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            # Start memory tracing
            tracemalloc.start()
            
            # Run benchmark
            start_time = time.time()
            for _ in range(iterations):
                func()
            end_time = time.time()
            
            # Get memory statistics
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            return {
                "test_name": test_name,
                "iterations": iterations,
                "duration_seconds": end_time - start_time,
                "initial_memory_mb": initial_memory,
                "final_memory_mb": final_memory,
                "memory_increase_mb": final_memory - initial_memory,
                "traced_current_mb": current / 1024 / 1024,
                "traced_peak_mb": peak / 1024 / 1024,
                "avg_memory_per_call_kb": (peak / iterations) / 1024 if iterations > 0 else 0
            }
            
        except ImportError:
            self.logger.warning("Memory profiling requires psutil and tracemalloc")
            return {"error": "Required modules not available"}
    
    def _percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile from data."""
        if not data:
            return 0.0
        
        sorted_data = sorted(data)
        n = len(sorted_data)
        index = (percentile / 100) * (n - 1)
        
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get summary of all performance test results."""
        if not self.results_history:
            return {"message": "No performance tests have been run"}
        
        # Calculate aggregated statistics
        total_tests = len(self.results_history)
        avg_rps = statistics.mean([r.requests_per_second for r in self.results_history])
        avg_error_rate = statistics.mean([r.error_rate_percent for r in self.results_history])
        
        best_performance = max(self.results_history, key=lambda r: r.requests_per_second)
        worst_performance = min(self.results_history, key=lambda r: r.requests_per_second)
        
        return {
            "total_tests": total_tests,
            "average_rps": avg_rps,
            "average_error_rate": avg_error_rate,
            "best_performance": {
                "test": best_performance.test_name,
                "rps": best_performance.requests_per_second
            },
            "worst_performance": {
                "test": worst_performance.test_name,
                "rps": worst_performance.requests_per_second
            },
            "recent_tests": [
                {
                    "name": r.test_name,
                    "rps": r.requests_per_second,
                    "error_rate": r.error_rate_percent
                } for r in self.results_history[-5:]  # Last 5 tests
            ]
        }
    
    def export_results(self, filename: str = None) -> str:
        """Export all results to JSON file."""
        if filename is None:
            filename = f"performance_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            "export_time": datetime.now().isoformat(),
            "total_tests": len(self.results_history),
            "summary": self.get_performance_summary(),
            "detailed_results": [
                {
                    "test_name": r.test_name,
                    "total_requests": r.total_requests,
                    "successful_requests": r.successful_requests,
                    "failed_requests": r.failed_requests,
                    "duration_seconds": r.duration_seconds,
                    "requests_per_second": r.requests_per_second,
                    "avg_response_time_ms": r.avg_response_time_ms,
                    "min_response_time_ms": r.min_response_time_ms,
                    "max_response_time_ms": r.max_response_time_ms,
                    "p95_response_time_ms": r.p95_response_time_ms,
                    "p99_response_time_ms": r.p99_response_time_ms,
                    "error_rate_percent": r.error_rate_percent,
                    "sample_errors": r.errors
                } for r in self.results_history
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.logger.info(f"Performance results exported to {filename}")
        return filename

# Global performance tester instance
_performance_tester: Optional[PerformanceTester] = None

def get_performance_tester() -> PerformanceTester:
    """Get global performance tester instance."""
    global _performance_tester
    if _performance_tester is None:
        _performance_tester = PerformanceTester()
    return _performance_tester

# Decorator for easy performance testing
def benchmark(iterations: int = 100):
    """Decorator to benchmark function performance."""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Run actual function
            result = func(*args, **kwargs)
            
            # Run benchmark
            tester = get_performance_tester()
            benchmark_result = tester.benchmark_function(
                lambda: func(*args, **kwargs), 
                iterations=iterations,
                name=func.__name__
            )
            
            # Log result
            logger.info(
                f"Benchmark {func.__name__}: "
                f"{benchmark_result.requests_per_second:.2f} ops/sec, "
                f"{benchmark_result.avg_response_time_ms:.2f}ms avg"
            )
            
            return result
        return wrapper
    return decorator

if __name__ == "__main__":
    # Example performance tests
    tester = get_performance_tester()
    
    # Simple function to benchmark
    def example_function():
        """Example function for testing."""
        sum(i**2 for i in range(100))
        time.sleep(0.001)  # Simulate some work
    
    def example_heavy_function():
        """Example heavy function."""
        sum(i**2 for i in range(1000))
        time.sleep(0.01)
    
    # Run benchmarks
    print("Running performance tests...")
    
    # Single function benchmark
    result1 = tester.benchmark_function(example_function, iterations=500)
    print(f"Light function: {result1.requests_per_second:.2f} ops/sec")
    
    # Load test
    config = LoadTestConfig(
        name="example_load_test",
        target_function=example_function,
        num_requests=1000,
        concurrent_users=10,
        duration_seconds=10
    )
    result2 = tester.load_test(config)
    print(f"Load test: {result2.requests_per_second:.2f} RPS")
    
    # Benchmark suite
    functions = {
        "light_function": example_function,
        "heavy_function": example_heavy_function
    }
    results = tester.benchmark_suite(functions, iterations=100)
    
    for name, result in results.items():
        print(f"{name}: {result.requests_per_second:.2f} ops/sec")
    
    # Export results
    filename = tester.export_results()
    print(f"Results exported to: {filename}")
    
    # Print summary
    summary = tester.get_performance_summary()
    print(f"Performance Summary: {json.dumps(summary, indent=2)}")