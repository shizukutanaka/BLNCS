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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
