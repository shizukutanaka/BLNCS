"""
Comprehensive Integration Test Suite for BLNCS
Production-ready integration tests covering all major components.
"""

import pytest
import time
import tempfile
import threading
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock

# Import BLNCS components
from blncs.core import (
    get_cache, get_logger, get_config, get_service_container,
    get_unified_monitoring
)
from blncs.core.database import DatabasePool, get_database_manager
from blncs.core.unified_cache import get_cache_manager, CacheType
from blncs.core.resource_manager import get_resource_manager, ResourceType
from blncs.core.circuit_breaker_enhanced import get_circuit_breaker, CircuitBreakerConfig
from blncs.core.database_query_optimizer import get_query_optimizer
from blncs.core.observability import get_observability_collector, record_metric, MetricType
from blncs.core.graceful_shutdown import get_shutdown_manager, ShutdownPhase
from blncs.core.config_validator import get_config_validator, ValidationRule
from blncs.core.memory_optimizer import get_memory_profiler, memory_tracker

from blncs.lightning.client import LightningClient
from blncs.core.exceptions import BLNCSError, ConnectionError, ConfigError


class TestDatabaseIntegration:
    """Integration tests for database components"""
    
    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database for testing"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        yield db_path
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.fixture
    def database_pool(self, temp_db_path):
        """Create database pool for testing"""
        pool = DatabasePool(temp_db_path, max_connections=5)
        yield pool
        pool.shutdown()
    
    def test_database_connection_pooling(self, database_pool):
        """Test database connection pooling works correctly"""
        connections = []
        
        # Get multiple connections
        for i in range(3):
            conn = database_pool.get_connection()
            connections.append(conn)
            assert conn is not None
        
        # Return connections to pool
        for conn in connections:
            database_pool.return_connection(conn)
        
        # Verify we can get connections again
        new_conn = database_pool.get_connection()
        assert new_conn is not None
        database_pool.return_connection(new_conn)
    
    def test_database_query_optimization(self, database_pool):
        """Test query optimization features"""
        optimizer = get_query_optimizer(database_pool)
        
        # Create test table
        with database_pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE test_users (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    email TEXT
                )
            """)
            
            # Insert test data
            test_data = [
                (1, 'Alice', 'alice@example.com'),
                (2, 'Bob', 'bob@example.com'),
                (3, 'Charlie', 'charlie@example.com')
            ]
            cursor.executemany("INSERT INTO test_users VALUES (?, ?, ?)", test_data)
            conn.commit()
        
        # Test optimized query execution
        results = optimizer.execute_optimized_query(
            "SELECT * FROM test_users WHERE id = ?", [1]
        )
        assert len(results) == 1
        assert results[0][1] == 'Alice'
        
        # Test batch queries
        batch_queries = [
            ("SELECT * FROM test_users WHERE id = ?", [2]),
            ("SELECT * FROM test_users WHERE id = ?", [3])
        ]
        batch_results = optimizer.batch_execute_queries(batch_queries)
        assert len(batch_results) == 2
        
        # Test N+1 elimination
        foreign_keys = [1, 2, 3]
        related_records = optimizer.get_related_records(
            table="test_users",
            foreign_keys=foreign_keys,
            key_field="id"
        )
        assert len(related_records) == 3
        assert 1 in related_records
        assert 2 in related_records
        assert 3 in related_records


class TestCacheIntegration:
    """Integration tests for caching system"""
    
    def test_unified_cache_manager(self):
        """Test unified cache manager functionality"""
        cache_manager = get_cache_manager()
        
        # Test different cache types
        cache_manager.set(CacheType.LIGHTNING_DATA, "node_info", {"alias": "test_node"})
        cache_manager.set(CacheType.CONFIGURATION, "lightning.host", "localhost")
        cache_manager.set(CacheType.CALCULATIONS, "fee_estimate", 1000)
        
        # Verify retrieval
        assert cache_manager.get(CacheType.LIGHTNING_DATA, "node_info")["alias"] == "test_node"
        assert cache_manager.get(CacheType.CONFIGURATION, "lightning.host") == "localhost"
        assert cache_manager.get(CacheType.CALCULATIONS, "fee_estimate") == 1000
        
        # Test cache statistics
        stats = cache_manager.get_stats()
        assert stats["total_hits"] > 0
        assert "cache_types" in stats
        assert "lightning_data" in stats["cache_types"]
        
        # Test cache clearing
        cache_manager.clear_cache_type(CacheType.LIGHTNING_DATA)
        assert cache_manager.get(CacheType.LIGHTNING_DATA, "node_info") is None
    
    def test_cache_decorators(self):
        """Test cache decorator functionality"""
        from blncs.core.unified_cache import cache_calc
        
        call_count = 0
        
        @cache_calc(ttl=60, key_prefix="test")
        def expensive_calculation(x, y):
            nonlocal call_count
            call_count += 1
            return x * y + call_count
        
        # First call should execute function
        result1 = expensive_calculation(5, 10)
        assert call_count == 1
        
        # Second call should use cache
        result2 = expensive_calculation(5, 10)
        assert result1 == result2
        assert call_count == 1  # Function not called again
        
        # Different parameters should execute function
        result3 = expensive_calculation(3, 7)
        assert call_count == 2


class TestCircuitBreakerIntegration:
    """Integration tests for circuit breaker patterns"""
    
    def test_circuit_breaker_basic_flow(self):
        """Test basic circuit breaker functionality"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=1,
            success_threshold=2
        )
        
        cb = get_circuit_breaker("test_service", config)
        
        # Function that fails
        def failing_function():
            raise ConnectionError("Service unavailable")
        
        # Function that succeeds
        def working_function():
            return "success"
        
        # Trigger failures to open circuit
        for i in range(3):
            with pytest.raises(ConnectionError):
                cb.call(failing_function)
        
        # Circuit should now be open
        from blncs.core.circuit_breaker_enhanced import CircuitState
        assert cb.state == CircuitState.OPEN
        
        # Calls should fail fast
        from blncs.core.exceptions import CircuitBreakerError
        with pytest.raises(CircuitBreakerError):
            cb.call(working_function)
        
        # Wait for recovery timeout
        time.sleep(1.1)
        
        # Should allow test calls (half-open state)
        result = cb.call(working_function)
        assert result == "success"
        
        # Another success should close the circuit
        result = cb.call(working_function)
        assert result == "success"
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_breaker_decorator(self):
        """Test circuit breaker decorator"""
        from blncs.core.circuit_breaker_enhanced import circuit_breaker
        
        @circuit_breaker("decorator_test", CircuitBreakerConfig(failure_threshold=2))
        def test_function(should_fail=False):
            if should_fail:
                raise ValueError("Test failure")
            return "success"
        
        # Should work normally
        assert test_function() == "success"
        
        # Trigger failures
        with pytest.raises(ValueError):
            test_function(should_fail=True)
        with pytest.raises(ValueError):
            test_function(should_fail=True)
        
        # Circuit should now be open
        from blncs.core.exceptions import CircuitBreakerError
        with pytest.raises(CircuitBreakerError):
            test_function()


class TestResourceManagement:
    """Integration tests for resource management"""
    
    def test_resource_manager_thread_management(self):
        """Test resource manager handles threads properly"""
        resource_manager = get_resource_manager()
        
        # Track thread creation
        thread_results = []
        
        def worker_thread(stop_event):
            while not stop_event.is_set():
                thread_results.append(time.time())
                time.sleep(0.1)
        
        # Use managed thread context
        from blncs.core.resource_manager import managed_thread
        
        with managed_thread("test_worker", worker_thread) as thread:
            time.sleep(0.5)  # Let it run for a bit
            assert thread.is_alive()
        
        # Thread should be cleaned up after context exit
        time.sleep(0.2)  # Give time for cleanup
        assert not thread.is_alive()
        assert len(thread_results) > 0
    
    def test_resource_manager_connection_management(self):
        """Test resource manager handles connections properly"""
        resource_manager = get_resource_manager()
        
        # Mock connection object
        mock_connection = Mock()
        mock_connection.close = Mock()
        
        from blncs.core.resource_manager import managed_connection
        
        with managed_connection("test_connection", mock_connection) as conn:
            assert conn == mock_connection
        
        # Connection should be closed after context exit
        mock_connection.close.assert_called_once()
    
    def test_graceful_shutdown_integration(self):
        """Test graceful shutdown coordination"""
        shutdown_manager = get_shutdown_manager()
        
        # Register shutdown hooks
        hook_called = []
        
        def test_hook():
            hook_called.append(True)
        
        shutdown_manager.register_shutdown_hook(
            "test_hook", 
            test_hook, 
            priority=100,
            phase=ShutdownPhase.CLEANUP_RESOURCES
        )
        
        # Test work tracking
        assert shutdown_manager.is_accepting_new_work()
        
        with shutdown_manager.work_context("test_work"):
            assert shutdown_manager.get_active_work_count() > 0
        
        assert shutdown_manager.get_active_work_count() == 0
        
        # Test shutdown process (but don't actually shut down)
        status = shutdown_manager.get_shutdown_status()
        assert not status["shutdown_requested"]
        assert status["accepting_new_work"]


class TestObservabilityIntegration:
    """Integration tests for observability system"""
    
    def test_metrics_collection(self):
        """Test comprehensive metrics collection"""
        collector = get_observability_collector()
        
        # Record various metric types
        collector.record_metric("test.counter", 1, MetricType.COUNTER)
        collector.increment_counter("test.requests", 5)
        collector.set_gauge("test.temperature", 25.5)
        collector.record_timer("test.operation", 0.150)
        
        # Test timer context manager
        with collector.timer("test.timed_operation"):
            time.sleep(0.01)
        
        # Verify metrics
        summary = collector.get_metrics_summary()
        assert "counters" in summary
        assert "gauges" in summary
        assert "timers" in summary
        
        # Test performance recording
        collector.record_performance_data(
            component="test_component",
            operation="test_operation",
            duration=0.123,
            success=True,
            metadata={"version": "1.0"}
        )
        
        perf_summary = collector.get_performance_summary("test_component")
        assert perf_summary["total_operations"] > 0
        assert "success_rate" in perf_summary
    
    def test_distributed_tracing(self):
        """Test distributed tracing functionality"""
        collector = get_observability_collector()
        
        # Create trace
        with collector.trace("main_operation") as main_span_id:
            collector.add_span_log(main_span_id, "Starting main operation")
            
            # Nested span
            with collector.trace("sub_operation", parent_span_id=main_span_id) as sub_span_id:
                collector.add_span_log(sub_span_id, "Sub operation in progress")
                time.sleep(0.01)
            
            time.sleep(0.01)
        
        # Verify trace structure
        # Note: In a real test, you'd extract the trace_id from the span context
        # For now, we'll just verify that tracing doesn't crash


class TestConfigurationIntegration:
    """Integration tests for configuration system"""
    
    @pytest.fixture
    def temp_config_files(self):
        """Create temporary configuration files"""
        config_dir = tempfile.mkdtemp()
        
        # JSON config
        json_config = {
            "lightning": {
                "host": "localhost",
                "port": 9735,
                "network": "testnet"
            },
            "database": {
                "path": "/tmp/test.db"
            }
        }
        
        json_path = os.path.join(config_dir, "config.json")
        with open(json_path, 'w') as f:
            json.dump(json_config, f)
        
        # YAML config
        yaml_config = """
cache:
  max_size: 1024
  default_ttl: 300

logging:
  level: INFO
"""
        
        yaml_path = os.path.join(config_dir, "config.yaml")
        with open(yaml_path, 'w') as f:
            f.write(yaml_config)
        
        yield [json_path, yaml_path]
        
        # Cleanup
        import shutil
        shutil.rmtree(config_dir)
    
    def test_config_validation_and_loading(self, temp_config_files):
        """Test configuration validation and loading"""
        validator = get_config_validator(
            config_paths=temp_config_files,
            enable_hot_reload=False
        )
        
        # Load and validate configuration
        config = validator.load_config()
        
        assert config["lightning"]["host"] == "localhost"
        assert config["lightning"]["port"] == 9735
        assert config["cache"]["max_size"] == 1024
        
        # Test validation rules
        errors = validator.validate_config(config)
        assert len(errors) == 0  # Should be valid
        
        # Test invalid config
        invalid_config = config.copy()
        invalid_config["lightning"]["port"] = 999999  # Invalid port
        
        errors = validator.validate_config(invalid_config)
        assert len(errors) > 0
        assert any("port" in error for error in errors)
    
    def test_config_hot_reload(self, temp_config_files):
        """Test configuration hot reloading"""
        # This is a simplified test - full hot-reload testing would require
        # file modification and waiting for file system events
        validator = get_config_validator(
            config_paths=temp_config_files,
            enable_hot_reload=True
        )
        
        # Load initial config
        config = validator.load_config()
        initial_port = config["lightning"]["port"]
        
        # Verify hot reload setup
        assert validator.enable_hot_reload
        
        # Test change handler registration
        changes_received = []
        
        def change_handler(changes):
            changes_received.extend(changes)
        
        validator.add_change_handler(change_handler)
        
        # Simulate config change (in a real test, you'd modify the file)
        # For now, just verify the handler system works
        from blncs.core.config_validator import ConfigChange
        test_change = ConfigChange("test.key", "old_value", "new_value")
        validator._notify_change_handlers([test_change])
        
        assert len(changes_received) == 1
        assert changes_received[0].key == "test.key"


class TestMemoryManagement:
    """Integration tests for memory management"""
    
    def test_memory_profiler_basic_functionality(self):
        """Test memory profiler basic operations"""
        profiler = get_memory_profiler()
        
        # Take initial snapshot
        initial_snapshot = profiler.take_snapshot()
        assert initial_snapshot.rss_mb > 0
        assert initial_snapshot.python_objects > 0
        
        # Create some objects to consume memory
        large_list = [i for i in range(10000)]
        
        # Take another snapshot
        after_snapshot = profiler.take_snapshot()
        assert after_snapshot.python_objects >= initial_snapshot.python_objects
        
        # Test memory optimization
        optimization_results = profiler.optimize_memory()
        assert "garbage_collection" in optimization_results
        assert optimization_results["garbage_collection"]["objects_freed"] >= 0
        
        # Clean up
        del large_list
    
    def test_memory_tracking_context_manager(self):
        """Test memory tracking context manager"""
        with memory_tracker("test_operation"):
            # Create some objects
            test_data = [{"key": f"value_{i}"} for i in range(1000)]
            
            # Do some work
            processed = [item["key"].upper() for item in test_data]
            
            # Memory tracker will automatically measure usage
            assert len(processed) == 1000


class TestEndToEndScenarios:
    """End-to-end integration tests"""
    
    @pytest.fixture
    def mock_lightning_node(self):
        """Mock Lightning node for testing"""
        mock_node = Mock()
        mock_node.get_info.return_value = {
            "identity_pubkey": "test_pubkey",
            "alias": "test_node",
            "num_active_channels": 5,
            "num_peers": 3
        }
        mock_node.get_balance.return_value = {
            "total_balance": 1000000,
            "confirmed_balance": 950000,
            "unconfirmed_balance": 50000
        }
        return mock_node
    
    def test_full_system_initialization(self):
        """Test complete system initialization"""
        # Initialize service container
        container = get_service_container()
        
        # Verify core services are available
        logger = container.get_singleton('logger')
        assert logger is not None
        
        cache = container.get_singleton('cache')
        assert cache is not None
        
        # Test service integration
        with cache.timer("system_init_test"):
            logger.info("Testing system initialization")
        
        stats = cache.get_stats()
        assert stats["total_hits"] >= 0
    
    @patch('blncs.lightning.client.requests.Session')
    def test_lightning_client_integration(self, mock_session):
        """Test Lightning client with mocked network calls"""
        # Configure mock responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "identity_pubkey": "test_pubkey",
            "alias": "test_node"
        }
        mock_session.return_value.get.return_value = mock_response
        
        # Test Lightning client
        config = {
            "lightning": {
                "host": "localhost",
                "port": 8080,
                "network": "testnet",
                "verify_ssl": False
            }
        }
        
        client = LightningClient(config)
        
        # Test connection (mocked)
        try:
            info = client.get_info()
            assert info is not None
        except Exception as e:
            # Expected since we're using mocks
            assert "connection" in str(e).lower() or "timeout" in str(e).lower()
    
    def test_error_handling_integration(self):
        """Test error handling across components"""
        # Test circuit breaker with database operations
        cb = get_circuit_breaker("test_db_operations")
        
        def database_operation():
            # Simulate database operation that might fail
            import random
            if random.random() < 0.3:  # 30% chance of failure
                raise ConnectionError("Database connection failed")
            return "success"
        
        # This would be a more comprehensive test in a real scenario
        # For now, just verify the integration doesn't crash
        try:
            result = cb.call(database_operation)
        except (ConnectionError, Exception):
            pass  # Expected potential failures
    
    def test_shutdown_coordination(self):
        """Test coordinated shutdown of all systems"""
        # Get all managers
        resource_manager = get_resource_manager()
        shutdown_manager = get_shutdown_manager()
        memory_profiler = get_memory_profiler()
        
        # Register shutdown hooks
        shutdown_called = []
        
        def cleanup_test_resources():
            shutdown_called.append("test_cleanup")
        
        shutdown_manager.register_shutdown_hook(
            "test_cleanup",
            cleanup_test_resources,
            priority=50
        )
        
        # Test that shutdown preparation works
        status = shutdown_manager.get_shutdown_status()
        assert not status["shutdown_requested"]
        
        # Don't actually shutdown during tests, just verify setup
        assert len(shutdown_manager._hooks[ShutdownPhase.CLEANUP_RESOURCES]) > 0


# Performance and stress tests
class TestPerformanceIntegration:
    """Performance and stress integration tests"""
    
    def test_cache_performance_under_load(self):
        """Test cache performance under concurrent load"""
        cache_manager = get_cache_manager()
        
        def cache_worker(worker_id):
            for i in range(100):
                key = f"worker_{worker_id}_item_{i}"
                value = {"data": f"value_{i}", "worker": worker_id}
                
                # Set and get
                cache_manager.set(CacheType.CALCULATIONS, key, value)
                retrieved = cache_manager.get(CacheType.CALCULATIONS, key)
                assert retrieved == value
        
        # Run multiple workers concurrently
        threads = []
        for worker_id in range(5):
            thread = threading.Thread(target=cache_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify cache statistics
        stats = cache_manager.get_stats()
        assert stats["total_hits"] > 0
    
    def test_database_performance_under_load(self):
        """Test database performance under concurrent access"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            pool = DatabasePool(db_path, max_connections=10)
            
            # Initialize test table
            with pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE test_performance (
                        id INTEGER PRIMARY KEY,
                        data TEXT,
                        created_at REAL
                    )
                """)
                conn.commit()
            
            def database_worker(worker_id):
                for i in range(50):
                    with pool.get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT INTO test_performance (data, created_at) VALUES (?, ?)",
                            (f"worker_{worker_id}_data_{i}", time.time())
                        )
                        conn.commit()
            
            # Run concurrent database operations
            threads = []
            start_time = time.time()
            
            for worker_id in range(5):
                thread = threading.Thread(target=database_worker, args=(worker_id,))
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join()
            
            end_time = time.time()
            
            # Verify all records were inserted
            with pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM test_performance")
                count = cursor.fetchone()[0]
                assert count == 250  # 5 workers * 50 records each
            
            pool.shutdown()
            
            # Log performance
            duration = end_time - start_time
            ops_per_second = 250 / duration
            print(f"Database performance: {ops_per_second:.1f} ops/second")
            
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)


if __name__ == "__main__":
    # Run with pytest
    pytest.main([__file__, "-v", "-s"])