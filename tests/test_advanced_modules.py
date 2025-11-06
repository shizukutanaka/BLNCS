#!/usr/bin/env python3
"""
Comprehensive tests for advanced modules
Tests all new enterprise-grade implementations
"""

import pytest
import asyncio
from datetime import datetime, timedelta

# Health Probes
from blncs.core.health_probes import (
    HealthProbeManager, ProbeConfig, ProbeType, ProbeStatus
)

# Idempotency
from blncs.core.idempotency import (
    IdempotencyManager, TransactionStatus, DistributedLock
)

# Dependency Injection
from blncs.core.dependency_container import (
    ServiceContainer, ServiceCollection, LifecycleScope
)

# DDD
from blncs.core.ddd_foundation import (
    ValueObject, Money, Entity, Aggregate
)

# Event Sourcing
from blncs.core.event_sourcing_patterns import (
    Event, InMemoryEventStore, InMemoryEventPublisher, EventSourcing
)

# Resilience
from blncs.core.resilience_patterns import (
    CircuitBreaker, Bulkhead, Retry
)

# Observability
from blncs.core.observability import (
    StructuredLogger, MetricsCollector, TracingManager
)

# Performance Acceleration
from blncs.core.performance_acceleration import (
    NumpyOptimizer, RustFFIBridge, WebAssemblyBridge, HybridExecutor,
    OptimizationStrategy, AccelerationMethod
)

# Advanced Rate Limiting
from blncs.core.advanced_rate_limiting import (
    RateLimiter, RateLimitConfig, RateLimitStrategy, TokenBucketLimiter,
    LeakyBucketLimiter, SlidingWindowLimiter, FixedWindowLimiter
)

# Distributed Caching
from blncs.core.distributed_caching import (
    InMemoryCache, DistributedCacheLayer, EvictionPolicy, CacheWarmer,
    CacheInvalidator
)

# Consensus Algorithms
from blncs.core.consensus_algorithms import (
    RaftConsensus, PaxosConsensus, ConsensusCluster, NodeState
)


class TestHealthProbes:
    """Test health probe system"""

    @pytest.mark.asyncio
    async def test_health_probe_creation(self):
        """Test creating health probes"""
        manager = HealthProbeManager()

        async def mock_check():
            return True

        config = ProbeConfig(
            name="test_probe",
            probe_type=ProbeType.READINESS,
            check_func=mock_check
        )

        manager.register_probe(config)
        assert "test_probe" in manager.probes

    @pytest.mark.asyncio
    async def test_liveness_probe(self):
        """Test liveness probe execution"""
        manager = HealthProbeManager()

        call_count = 0

        async def liveness_check():
            nonlocal call_count
            call_count += 1
            return True

        config = ProbeConfig(
            name="liveness",
            probe_type=ProbeType.LIVENESS,
            check_func=liveness_check,
            timeout_seconds=5
        )

        manager.register_probe(config)
        result = await manager.run_probe("liveness")

        assert result.status == ProbeStatus.SUCCESS
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_readiness_status(self):
        """Test readiness status aggregation"""
        manager = HealthProbeManager()

        async def ready_check():
            return True

        config = ProbeConfig(
            name="ready",
            probe_type=ProbeType.READINESS,
            check_func=ready_check
        )

        manager.register_probe(config)
        await manager.run_probe("ready")

        assert manager.get_readiness_status() is True


class TestIdempotency:
    """Test idempotency system"""

    def test_transaction_creation(self):
        """Test creating transactions"""
        manager = IdempotencyManager()
        record = manager.create_transaction()

        assert record.status == TransactionStatus.PENDING
        assert record.transaction_id is not None

    def test_idempotency_key_deduplication(self):
        """Test deduplication by idempotency key"""
        manager = IdempotencyManager()

        key = "test_key_123"
        record1 = manager.create_transaction(idempotency_key=key)
        record2 = manager.create_transaction(idempotency_key=key)

        assert record1.transaction_id == record2.transaction_id

    def test_transaction_lifecycle(self):
        """Test transaction state transitions"""
        manager = IdempotencyManager()
        record = manager.create_transaction()
        tid = record.transaction_id

        manager.start_processing(tid)
        assert manager.get_transaction(tid).status == TransactionStatus.PROCESSING

        manager.complete_transaction(tid, {"result": "success"})
        assert manager.get_transaction(tid).status == TransactionStatus.COMPLETED

    def test_distributed_lock(self):
        """Test distributed lock"""
        lock = DistributedLock()

        assert lock.acquire_lock("resource_1") is True
        assert lock.is_locked("resource_1") is True
        assert lock.acquire_lock("resource_1") is False  # Already locked

        lock.release_lock("resource_1")
        assert lock.is_locked("resource_1") is False


class TestDependencyInjection:
    """Test dependency injection container"""

    def test_singleton_registration(self):
        """Test singleton service registration"""
        container = ServiceContainer()

        class MyService:
            pass

        container.register_singleton(MyService)
        instance1 = container.resolve(MyService)
        instance2 = container.resolve(MyService)

        assert instance1 is instance2

    def test_transient_registration(self):
        """Test transient service registration"""
        container = ServiceContainer()

        class MyService:
            pass

        container.register_transient(MyService)
        instance1 = container.resolve(MyService)
        instance2 = container.resolve(MyService)

        assert instance1 is not instance2

    def test_service_collection_builder(self):
        """Test service collection fluent builder"""
        class ServiceA:
            pass

        class ServiceB:
            pass

        collection = ServiceCollection()
        container = (collection
                     .add_singleton(ServiceA)
                     .add_transient(ServiceB)
                     .build())

        service_a = container.resolve(ServiceA)
        service_b = container.resolve(ServiceB)

        assert service_a is not None
        assert service_b is not None


class TestDDD:
    """Test Domain-Driven Design patterns"""

    def test_value_object_equality(self):
        """Test value object equality"""
        money1 = Money(100.0, "BTC")
        money2 = Money(100.0, "BTC")
        money3 = Money(200.0, "BTC")

        assert money1 == money2
        assert money1 != money3

    def test_value_object_immutability(self):
        """Test value object operations"""
        money = Money(100.0, "BTC")
        result = money.multiply(2.0)

        assert money.amount == 100.0  # Original unchanged
        assert result.amount == 200.0

    def test_entity_identity(self):
        """Test entity identity"""
        from blncs.core.ddd_foundation import Entity

        class TestEntity(Entity):
            def validate(self):
                pass

        entity1 = TestEntity(id="entity_1")
        entity2 = TestEntity(id="entity_1")

        assert entity1 == entity2  # Same ID = equal


class TestEventSourcing:
    """Test event sourcing system"""

    @pytest.mark.asyncio
    async def test_event_store_append(self):
        """Test appending events"""
        store = InMemoryEventStore()

        event = Event(
            event_id="evt_1",
            aggregate_id="agg_1",
            aggregate_type="TestAggregate",
            event_type="Created"
        )

        await store.append_event(event)
        events = await store.get_events("agg_1")

        assert len(events) == 1
        assert events[0].event_type == "Created"

    @pytest.mark.asyncio
    async def test_event_sourcing_integration(self):
        """Test event sourcing with store and publisher"""
        store = InMemoryEventStore()
        publisher = InMemoryEventPublisher()

        event = Event(
            event_id="evt_1",
            aggregate_id="agg_1",
            aggregate_type="TestAggregate",
            event_type="TestEvent"
        )

        event_sourcing = EventSourcing(store, publisher)

        await event_sourcing.append_and_publish([event])
        history = await event_sourcing.get_aggregate_history("agg_1")

        assert len(history) == 1


class TestResilience:
    """Test resilience patterns"""

    @pytest.mark.asyncio
    async def test_circuit_breaker_basic(self):
        """Test circuit breaker"""
        breaker = CircuitBreaker()

        call_count = 0

        async def failing_service():
            nonlocal call_count
            call_count += 1
            raise RuntimeError("Service error")

        # First few calls should fail
        for i in range(3):
            with pytest.raises(RuntimeError):
                await breaker.call(failing_service)

        # After threshold, should open circuit
        with pytest.raises(RuntimeError):
            await breaker.call(failing_service)

    @pytest.mark.asyncio
    async def test_bulkhead_concurrency_limit(self):
        """Test bulkhead limits concurrent calls"""
        from blncs.core.resilience_patterns import BulkheadConfig

        config = BulkheadConfig(max_concurrent_calls=2)
        bulkhead = Bulkhead(config)

        async def slow_operation():
            await asyncio.sleep(0.1)
            return "success"

        # Should allow 2 concurrent calls
        tasks = [
            bulkhead.call(slow_operation),
            bulkhead.call(slow_operation),
            bulkhead.call(slow_operation)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        assert any(isinstance(r, RuntimeError) for r in results)

    @pytest.mark.asyncio
    async def test_retry_with_success(self):
        """Test retry succeeds eventually"""
        retry = Retry(max_attempts=3, initial_delay_ms=10)

        call_count = 0

        async def eventually_succeeds():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("Not yet")
            return "success"

        result = await retry.execute(eventually_succeeds)
        assert result == "success"
        assert call_count == 2


class TestObservability:
    """Test observability system"""

    def test_structured_logger(self):
        """Test structured logging"""
        logger = StructuredLogger("test_logger")
        # Just verify it can be created and called
        logger.info("Test message", extra_field="value")

    def test_metrics_collector(self):
        """Test metrics collection"""
        collector = MetricsCollector()

        collector.increment_counter("requests")
        collector.increment_counter("requests")
        collector.set_gauge("temperature", 25.5)

        assert collector.get_counter("requests") == 2
        assert collector.get_gauge("temperature") == 25.5

    def test_tracing_manager(self):
        """Test distributed tracing"""
        manager = TracingManager()

        span = manager.start_span("operation_1")
        assert span.operation_name == "operation_1"

        manager.add_event(span.span_id, "event_1", {"data": "value"})
        assert len(span.events) == 1

        manager.end_span(span.span_id, status="OK")
        assert span.status == "OK"


class TestPerformanceAcceleration:
    """Test performance acceleration module"""

    def test_numpy_availability_check(self):
        """Test NumPy availability detection"""
        available = NumpyOptimizer.is_numpy_available()
        assert isinstance(available, bool)

    def test_numpy_vectorized_operation(self):
        """Test NumPy vectorized operations"""
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        result = NumpyOptimizer.vectorized_operation(data, lambda x: x * 2)

        assert len(result) == len(data)
        assert all(isinstance(x, (int, float)) for x in result)

    def test_numpy_matrix_multiplication(self):
        """Test optimized matrix multiplication"""
        matrix_a = [[1, 2], [3, 4]]
        matrix_b = [[5, 6], [7, 8]]

        result = NumpyOptimizer.matrix_multiplication(matrix_a, matrix_b)

        assert len(result) == 2
        assert len(result[0]) == 2
        assert result[0][0] == 19  # 1*5 + 2*7

    def test_numpy_reduce_memory_usage(self):
        """Test memory reduction with float32"""
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        result = NumpyOptimizer.reduce_memory_usage(data, dtype='float32')

        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_rust_ffi_expensive_operation(self):
        """Test Rust FFI bridge for expensive operations"""
        data = [1, 2, 3, 4, 5]
        result = RustFFIBridge.compute_expensive_operation(data)

        assert isinstance(result, int)
        assert result >= 0

    def test_rust_ffi_fft_computation(self):
        """Test FFT computation"""
        data = [1.0, 2.0, 3.0, 4.0]
        result = RustFFIBridge.fft_computation(data)

        assert len(result) == len(data)
        assert all(isinstance(x, complex) for x in result)

    def test_wasm_serialize_for_wasm(self):
        """Test WASM serialization"""
        float_data = [1.0, 2.0, 3.0]
        result = WebAssemblyBridge.serialize_for_wasm(float_data)

        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_wasm_deserialize_from_wasm(self):
        """Test WASM deserialization"""
        # Create serialized data
        float_data = [1.0, 2.0, 3.0]
        serialized = WebAssemblyBridge.serialize_for_wasm(float_data)

        # Deserialize
        result = WebAssemblyBridge.deserialize_from_wasm(serialized, 'float')

        assert len(result) == len(float_data)
        assert all(isinstance(x, float) for x in result)

    def test_wasm_compatible_transform(self):
        """Test WASM data transformation"""
        data = [1.0, 2.0, 3.0]
        result = WebAssemblyBridge.wasm_compatible_transform(data)

        assert len(result) == len(data)
        assert all(isinstance(x, float) for x in result)

    def test_hybrid_executor_acceleration_method_selection(self):
        """Test acceleration method selection"""
        executor = HybridExecutor()

        # Small data -> native
        method = executor.select_acceleration_method(
            data_size=100,
            operation_type="simple",
            available_libs={}
        )
        assert method == AccelerationMethod.NATIVE_PYTHON

        # Large data + NumPy -> NumPy
        method = executor.select_acceleration_method(
            data_size=50000,
            operation_type="matrix_mult",
            available_libs={'numpy': True}
        )
        assert method == AccelerationMethod.NUMPY

    def test_hybrid_executor_profiling(self):
        """Test profiling execution"""
        executor = HybridExecutor()

        def simple_operation(data):
            return sum(data)

        data = [1, 2, 3, 4, 5]
        result, metrics = executor.execute_with_profiling(
            simple_operation,
            data,
            AccelerationMethod.NATIVE_PYTHON
        )

        assert result == 15
        assert metrics.duration_ms >= 0
        assert metrics.method == AccelerationMethod.NATIVE_PYTHON

    def test_hybrid_executor_performance_report(self):
        """Test performance report generation"""
        executor = HybridExecutor()

        def test_op(data):
            return sum(data)

        executor.execute_with_profiling(
            test_op,
            [1, 2, 3],
            AccelerationMethod.NATIVE_PYTHON
        )

        report = executor.get_performance_report()

        assert report['total_operations'] == 1
        assert 'total_time_ms' in report
        assert 'average_operation_time_ms' in report

    def test_optimization_strategy_loop_fusion(self):
        """Test loop fusion optimization"""
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        operations = [
            lambda x: x * 2,
            lambda x: x + 1,
            lambda x: x / 2
        ]

        result = OptimizationStrategy.loop_fusion(operations, data)

        assert len(result) == len(data)
        # First element: ((1*2)+1)/2 = 1.5
        assert abs(result[0] - 1.5) < 0.01

    def test_optimization_strategy_memory_pooling(self):
        """Test memory pooling calculation"""
        pool_info = OptimizationStrategy.memory_pooling(
            operation_count=100,
            data_size=1000
        )

        assert 'pool_size_mb' in pool_info
        assert 'chunk_size' in pool_info
        assert 'pre_allocated_chunks' in pool_info
        assert pool_info['pool_size_mb'] >= 0

    def test_optimization_strategy_vectorization_analysis(self):
        """Test vectorization analysis"""
        def sample_op(x):
            return x * 2

        analysis = OptimizationStrategy.vectorization_analysis(
            sample_op,
            [1.0, 2.0, 3.0]
        )

        assert analysis['vectorizable'] is True
        assert 'estimated_speedup' in analysis
        assert 'memory_reduction' in analysis


class TestAdvancedRateLimiting:
    """Test advanced rate limiting strategies"""

    def test_token_bucket_basic(self):
        """Test token bucket rate limiter"""
        limiter = TokenBucketLimiter(rate=10.0, capacity=100)

        # Should allow requests up to capacity
        assert limiter.allow_request() is True
        assert limiter.allow_request() is True

    def test_leaky_bucket_basic(self):
        """Test leaky bucket rate limiter"""
        limiter = LeakyBucketLimiter(rate=5.0, capacity=10)

        assert limiter.allow_request() is True
        assert limiter.get_queue_length() == 1

    def test_sliding_window_limiter(self):
        """Test sliding window rate limiter"""
        limiter = SlidingWindowLimiter(requests_per_window=10, window_seconds=60)

        for _ in range(10):
            assert limiter.allow_request() is True

        assert limiter.allow_request() is False

    def test_fixed_window_limiter(self):
        """Test fixed window rate limiter"""
        limiter = FixedWindowLimiter(requests_per_window=5, window_seconds=1)

        for _ in range(5):
            assert limiter.allow_request() is True

        assert limiter.allow_request() is False

    def test_rate_limiter_config(self):
        """Test rate limiter with configuration"""
        config = RateLimitConfig(
            requests_per_second=100.0,
            burst_capacity=500,
            strategy=RateLimitStrategy.TOKEN_BUCKET
        )

        limiter = RateLimiter(config)
        allowed, wait_time = limiter.check_limit("client_1")

        assert allowed is True
        assert wait_time is None

    def test_rate_limiter_multiple_clients(self):
        """Test rate limiter with multiple clients"""
        config = RateLimitConfig(requests_per_second=5.0)
        limiter = RateLimiter(config)

        # Client 1
        allowed1, _ = limiter.check_limit("client_1")
        assert allowed1 is True

        # Client 2
        allowed2, _ = limiter.check_limit("client_2")
        assert allowed2 is True

        # Different clients should have independent limits
        metrics1 = limiter.get_metrics("client_1")
        metrics2 = limiter.get_metrics("client_2")

        assert metrics1 is not None
        assert metrics2 is not None


class TestDistributedCaching:
    """Test distributed caching system"""

    def test_in_memory_cache_basic(self):
        """Test basic in-memory cache operations"""
        cache = InMemoryCache()

        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_cache_expiration(self):
        """Test cache entry expiration"""
        cache = InMemoryCache()

        cache.set("key1", "value1", ttl_seconds=1)
        assert cache.get("key1") == "value1"

        # Simulate expiration
        import time
        time.sleep(1.1)
        assert cache.get("key1") is None

    def test_cache_eviction_lru(self):
        """Test LRU eviction policy"""
        cache = InMemoryCache(
            max_size_bytes=80,
            eviction_policy=EvictionPolicy.LRU
        )

        cache.set("key1", "value1")
        cache.set("key2", "value2")

        # Access key1 to mark it as recently used
        cache.get("key1")

        # Add large entry to trigger eviction
        cache.set("key3", "x" * 100)

        # key2 should be evicted (least recently used)
        metrics = cache.get_metrics()
        assert metrics.evictions >= 1

    def test_cache_metrics(self):
        """Test cache metrics"""
        cache = InMemoryCache()

        cache.set("key1", "value1")
        cache.get("key1")  # Hit
        cache.get("key2")  # Miss

        metrics = cache.get_metrics()
        assert metrics.cache_hits == 1
        assert metrics.cache_misses == 1
        assert metrics.hit_rate == 50.0

    def test_distributed_cache_layer(self):
        """Test multi-level cache"""
        l1_cache = InMemoryCache()
        cache_layer = DistributedCacheLayer(l1_cache)

        cache_layer.set("key1", "value1")
        assert cache_layer.get("key1") == "value1"

    def test_cache_warmer(self):
        """Test cache warming"""
        cache = InMemoryCache()
        warmer = CacheWarmer(cache)

        warmer.register_warm_data("key1", "value1")
        warmer.register_warm_data("key2", "value2")

        warmer.warm_cache()

        assert cache.get("key1") == "value1"
        assert cache.get("key2") == "value2"

    def test_cache_invalidator(self):
        """Test cache invalidation"""
        cache = InMemoryCache()
        invalidator = CacheInvalidator(cache)

        cache.set("key1", "value1")
        cache.set("key2", "value2")

        invalidator.register_dependency("key1", "key2")
        count = invalidator.invalidate("key1")

        assert count == 2
        assert cache.get("key1") is None


class TestConsensusAlgorithms:
    """Test consensus algorithms"""

    def test_raft_node_creation(self):
        """Test Raft node creation"""
        peers = {"node2", "node3"}
        node = RaftConsensus("node1", peers)

        assert node.node.node_id == "node1"
        assert node.node.state == NodeState.FOLLOWER

    def test_raft_election(self):
        """Test Raft leader election"""
        node = RaftConsensus("node1", {"node2", "node3"})

        initial_state = node.node.state
        node.start_election()

        # Should become candidate initially
        assert node.node.state in [NodeState.CANDIDATE, NodeState.LEADER]

    def test_raft_log_entry(self):
        """Test Raft log entry appending"""
        node = RaftConsensus("node1", set())
        node.node.state = NodeState.LEADER

        success = node.append_log_entry("SET", {"key": "value"})
        assert success is True
        assert len(node.node.log) == 1

    def test_raft_vote_granting(self):
        """Test Raft vote request handling"""
        node = RaftConsensus("node1", {"node2"})

        # Grant vote to candidate
        result = node.request_vote("node2", 1)
        assert result is True

        # Don't grant second vote in same term
        result = node.request_vote("node3", 1)
        assert result is False

    def test_raft_heartbeat(self):
        """Test Raft heartbeat"""
        node = RaftConsensus("node1", {"node2"})
        node.node.state = NodeState.LEADER

        # Should not raise exception
        node.send_heartbeat()

    def test_paxos_prepare_phase(self):
        """Test Paxos prepare phase"""
        node = PaxosConsensus("node1", {"node2", "node3"})

        result, data = node.prepare(1)
        assert result is True
        assert data['promised_number'] == 1

    def test_paxos_accept_phase(self):
        """Test Paxos accept phase"""
        node = PaxosConsensus("node1", {"node2", "node3"})

        node.prepare(1)
        result = node.accept(1, "value1")
        assert result is True
        assert node.get_accepted_value() == "value1"

    def test_paxos_learner(self):
        """Test Paxos learner"""
        node = PaxosConsensus("node1", {"node2", "node3"})

        node.learn(1, "value1", "proposer1")
        assert 1 in node.accepted_proposals

    def test_consensus_cluster_raft(self):
        """Test Raft cluster"""
        cluster = ConsensusCluster(algorithm="raft")

        cluster.add_node("node1", set())
        cluster.add_node("node2", {"node1"})

        node1 = cluster.get_node("node1")
        assert node1 is not None

    def test_consensus_cluster_paxos(self):
        """Test Paxos cluster"""
        cluster = ConsensusCluster(algorithm="paxos")

        cluster.add_node("node1", set())
        cluster.add_node("node2", {"node1"})

        metrics = cluster.get_metrics()
        assert metrics['algorithm'] == "paxos"
        assert metrics['node_count'] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
