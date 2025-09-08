#!/usr/bin/env python3
"""
Performance tests for BLNCS core components
Tests speed, resource usage, and scalability.
"""

import time
import pytest
import threading
import concurrent.futures
from typing import List
import statistics

# Import core components
from blncs.core.fast_cache import FastCache, get_fast_cache
from blncs.core.connection_pool import ConnectionPool, RequestCache
from blncs.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from blncs.core.metrics import MetricsCollector, Timer
from blncs.core.backup_enhanced import EnhancedBackupManager


class TestCachePerformance:
    """Test cache system performance"""
    
    def test_cache_speed(self):
        """Test cache read/write speed"""
        cache = FastCache(max_size=1000)
        
        # Write performance
        start = time.time()
        for i in range(10000):
            cache.set(f"key_{i}", f"value_{i}", ttl=300)
        write_time = time.time() - start
        writes_per_sec = 10000 / write_time
        
        assert writes_per_sec > 10000, f"Cache writes too slow: {writes_per_sec:.0f}/s"
        
        # Read performance (hits)
        start = time.time()
        for i in range(10000):
            value = cache.get(f"key_{i % 1000}")
        read_time = time.time() - start
        reads_per_sec = 10000 / read_time
        
        assert reads_per_sec > 50000, f"Cache reads too slow: {reads_per_sec:.0f}/s"
        
        print(f"Cache Performance: {writes_per_sec:.0f} writes/s, {reads_per_sec:.0f} reads/s")
    
    def test_cache_memory_efficiency(self):
        """Test cache memory usage"""
        cache = FastCache(max_size=1000)
        
        # Fill cache
        for i in range(1000):
            cache.set(f"key_{i}", f"value_{i}" * 100)  # ~100 bytes per value
        
        # Check LRU eviction works
        cache.set("new_key", "new_value")
        assert len(cache._cache) <= 1000
        
        # Check cleanup
        expired_count = cache.cleanup_expired()
        assert expired_count >= 0
    
    def test_cache_concurrency(self):
        """Test cache under concurrent access"""
        cache = get_fast_cache()
        errors = []
        
        def worker(worker_id: int):
            try:
                for i in range(100):
                    key = f"worker_{worker_id}_key_{i}"
                    cache.set(key, i)
                    value = cache.get(key)
                    assert value == i
            except Exception as e:
                errors.append(e)
        
        # Run concurrent workers
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            concurrent.futures.wait(futures)
        
        assert len(errors) == 0, f"Concurrency errors: {errors}"


class TestConnectionPoolPerformance:
    """Test connection pool performance"""
    
    def test_connection_pool_speed(self):
        """Test connection acquisition/release speed"""
        pool = ConnectionPool(max_connections=10)
        
        # Connection acquisition
        times = []
        for _ in range(100):
            start = time.time()
            conn = pool.get_connection("localhost", 8080)
            pool.release_connection("localhost", 8080, failed=False, latency=0.01)
            times.append(time.time() - start)
        
        avg_time = statistics.mean(times)
        assert avg_time < 0.001, f"Connection pool too slow: {avg_time*1000:.2f}ms avg"
        
        # Check stats
        stats = pool.get_pool_stats()
        assert stats['total_requests'] >= 100
        assert stats['success_rate'] > 0.99
    
    def test_connection_pool_concurrency(self):
        """Test connection pool under concurrent load"""
        pool = ConnectionPool(max_connections=5)
        results = []
        
        def worker(worker_id: int):
            latencies = []
            for i in range(20):
                start = time.time()
                conn = pool.get_connection(f"host_{worker_id % 3}", 8080)
                time.sleep(0.001)  # Simulate work
                latency = time.time() - start
                pool.release_connection(f"host_{worker_id % 3}", 8080, 
                                       failed=(i % 10 == 0), latency=latency)
                latencies.append(latency)
            return latencies
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            for future in concurrent.futures.as_completed(futures):
                results.extend(future.result())
        
        avg_latency = statistics.mean(results)
        p95_latency = statistics.quantiles(results, n=20)[18]  # 95th percentile
        
        assert avg_latency < 0.01, f"High average latency: {avg_latency*1000:.2f}ms"
        assert p95_latency < 0.02, f"High P95 latency: {p95_latency*1000:.2f}ms"


class TestCircuitBreakerPerformance:
    """Test circuit breaker performance"""
    
    def test_circuit_breaker_overhead(self):
        """Test circuit breaker overhead on function calls"""
        config = CircuitBreakerConfig(
            failure_threshold=5,
            success_threshold=2,
            timeout=1.0
        )
        breaker = CircuitBreaker(config)
        
        call_count = 0
        
        @breaker
        def fast_function():
            nonlocal call_count
            call_count += 1
            return "success"
        
        # Measure overhead
        start = time.time()
        for _ in range(10000):
            result = fast_function()
            assert result == "success"
        elapsed = time.time() - start
        
        calls_per_sec = 10000 / elapsed
        assert calls_per_sec > 10000, f"Circuit breaker overhead too high: {calls_per_sec:.0f} calls/s"
        assert call_count == 10000
    
    def test_circuit_breaker_state_transitions(self):
        """Test circuit breaker state transition speed"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=0.1  # 100ms timeout
        )
        breaker = CircuitBreaker(config)
        
        def failing_function():
            raise Exception("Test failure")
        
        def success_function():
            return "success"
        
        # Trip the breaker
        for _ in range(3):
            try:
                breaker.call(failing_function)
            except:
                pass
        
        assert breaker.state.value == "open"
        
        # Wait for timeout
        time.sleep(0.11)
        
        # Should transition to half-open
        result = breaker.call(success_function)
        assert result == "success"
        assert breaker.state.value == "half_open"
        
        # One more success should close it
        result = breaker.call(success_function)
        assert breaker.state.value == "closed"


class TestMetricsPerformance:
    """Test metrics collection performance"""
    
    def test_metrics_recording_speed(self):
        """Test metric recording speed"""
        collector = MetricsCollector()
        
        # Counter performance
        counter = collector.counter("test_counter")
        start = time.time()
        for _ in range(10000):
            counter.increment()
        counter_time = time.time() - start
        counter_ops_per_sec = 10000 / counter_time
        
        assert counter_ops_per_sec > 100000, f"Counter too slow: {counter_ops_per_sec:.0f} ops/s"
        
        # Histogram performance
        histogram = collector.histogram("test_histogram")
        start = time.time()
        for i in range(10000):
            histogram.observe(i % 100)
        histogram_time = time.time() - start
        histogram_ops_per_sec = 10000 / histogram_time
        
        assert histogram_ops_per_sec > 50000, f"Histogram too slow: {histogram_ops_per_sec:.0f} ops/s"
    
    def test_timer_overhead(self):
        """Test timer decorator overhead"""
        collector = MetricsCollector()
        timer = collector.timer("test_timer")
        
        @timer.time_func
        def timed_function():
            time.sleep(0.001)
            return "done"
        
        # Measure overhead
        results = []
        for _ in range(100):
            start = time.time()
            result = timed_function()
            elapsed = time.time() - start
            results.append(elapsed)
            assert result == "done"
        
        # Check overhead (should be minimal)
        avg_time = statistics.mean(results)
        assert avg_time < 0.0015, f"Timer overhead too high: {(avg_time-0.001)*1000:.2f}ms"
    
    def test_metrics_export_performance(self):
        """Test metrics export performance"""
        collector = MetricsCollector()
        
        # Create many metrics
        for i in range(100):
            collector.counter(f"counter_{i}").increment(i)
            collector.gauge(f"gauge_{i}").set(i * 2)
            collector.histogram(f"histogram_{i}").observe(i * 0.1)
        
        # Export performance
        start = time.time()
        prometheus_output = collector.export_prometheus()
        export_time = time.time() - start
        
        assert export_time < 0.01, f"Export too slow: {export_time*1000:.2f}ms"
        assert len(prometheus_output) > 0


class TestBackupPerformance:
    """Test backup system performance"""
    
    @pytest.mark.skip(reason="Requires file system access")
    def test_backup_speed(self, tmp_path):
        """Test backup creation speed"""
        from blncs.core.backup_enhanced import BackupType
        
        # Create test data
        test_dir = tmp_path / "test_data"
        test_dir.mkdir()
        
        for i in range(100):
            file = test_dir / f"file_{i}.txt"
            file.write_text(f"Test content {i}" * 100)
        
        # Test backup speed
        manager = EnhancedBackupManager()
        manager.backup_dir = tmp_path / "backups"
        
        start = time.time()
        backup_info = manager.create_backup(
            backup_type=BackupType.FULL,
            sources=[str(test_dir)]
        )
        backup_time = time.time() - start
        
        files_per_sec = backup_info.file_count / backup_time
        assert files_per_sec > 50, f"Backup too slow: {files_per_sec:.0f} files/s"


class TestOverallPerformance:
    """Test overall system performance"""
    
    def test_system_under_load(self):
        """Test system performance under load"""
        # Initialize all components
        cache = get_fast_cache()
        pool = ConnectionPool(max_connections=10)
        collector = MetricsCollector()
        
        errors = []
        latencies = []
        
        def worker(worker_id: int):
            try:
                timer = collector.timer(f"worker_{worker_id}_time")
                
                for i in range(50):
                    with timer:
                        # Cache operations
                        cache.set(f"worker_{worker_id}_key_{i}", i)
                        value = cache.get(f"worker_{worker_id}_key_{i}")
                        
                        # Connection pool operations
                        conn = pool.get_connection("localhost", 8080 + worker_id)
                        time.sleep(0.001)  # Simulate work
                        pool.release_connection("localhost", 8080 + worker_id)
                        
                        # Metrics
                        collector.counter("operations").increment()
                        collector.histogram("operation_value").observe(i)
                    
                    latencies.append(timer.points[-1].value if timer.points else 0)
                    
            except Exception as e:
                errors.append(e)
        
        # Run load test
        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(worker, i) for i in range(20)]
            concurrent.futures.wait(futures)
        total_time = time.time() - start
        
        # Check results
        assert len(errors) == 0, f"Errors during load test: {errors}"
        
        # Calculate throughput
        total_operations = 20 * 50
        ops_per_sec = total_operations / total_time
        assert ops_per_sec > 500, f"Low throughput: {ops_per_sec:.0f} ops/s"
        
        # Check latencies
        if latencies:
            avg_latency = statistics.mean(latencies)
            p95_latency = statistics.quantiles(latencies, n=20)[18]
            
            assert avg_latency < 0.01, f"High average latency: {avg_latency*1000:.2f}ms"
            assert p95_latency < 0.02, f"High P95 latency: {p95_latency*1000:.2f}ms"
        
        print(f"Load test: {ops_per_sec:.0f} ops/s, {avg_latency*1000:.2f}ms avg latency")


if __name__ == "__main__":
    # Run performance tests
    print("Running BLNCS Performance Tests...")
    
    # Cache tests
    cache_test = TestCachePerformance()
    cache_test.test_cache_speed()
    cache_test.test_cache_memory_efficiency()
    cache_test.test_cache_concurrency()
    
    # Connection pool tests
    pool_test = TestConnectionPoolPerformance()
    pool_test.test_connection_pool_speed()
    pool_test.test_connection_pool_concurrency()
    
    # Circuit breaker tests
    breaker_test = TestCircuitBreakerPerformance()
    breaker_test.test_circuit_breaker_overhead()
    breaker_test.test_circuit_breaker_state_transitions()
    
    # Metrics tests
    metrics_test = TestMetricsPerformance()
    metrics_test.test_metrics_recording_speed()
    metrics_test.test_timer_overhead()
    metrics_test.test_metrics_export_performance()
    
    # Overall performance
    overall_test = TestOverallPerformance()
    overall_test.test_system_under_load()
    
    print("All performance tests passed!")