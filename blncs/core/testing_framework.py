#!/usr/bin/env python3
"""
Test-Driven Development Framework
Production-ready testing utilities for enterprise applications
Based on 2024-2025 research on pytest and TDD best practices
"""

import logging
import time
from typing import Any, Callable, Optional, Dict, List, TypeVar, Generic
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
from functools import wraps
from enum import Enum

logger = logging.getLogger(__name__)

T = TypeVar('T')


class TestResultStatus(Enum):
    """Test result status"""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestCase:
    """Represents a single test case"""
    name: str
    test_func: Callable
    setup_func: Optional[Callable] = None
    teardown_func: Optional[Callable] = None
    timeout_seconds: Optional[float] = None
    skip_reason: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class TestMetrics:
    """Metrics for test execution"""
    test_name: str
    status: TestResultStatus
    duration_ms: float
    memory_used_mb: float = 0.0
    assertions_count: int = 0
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'test_name': self.test_name,
            'status': self.status.value,
            'duration_ms': self.duration_ms,
            'memory_used_mb': self.memory_used_mb,
            'assertions_count': self.assertions_count,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat()
        }


class AssertionHelper:
    """
    Assertion utilities for TDD
    Provides clear error messages for failed assertions
    """

    def __init__(self, test_name: str = ""):
        self.test_name = test_name
        self.assertion_count = 0

    def assert_equal(self, actual: Any, expected: Any, message: str = "") -> None:
        """Assert equality"""
        self.assertion_count += 1
        if actual != expected:
            error = f"Assertion failed: {actual} != {expected}"
            if message:
                error += f" ({message})"
            logger.error(error)
            raise AssertionError(error)

    def assert_true(self, condition: bool, message: str = "") -> None:
        """Assert condition is true"""
        self.assertion_count += 1
        if not condition:
            error = f"Assertion failed: condition is not true"
            if message:
                error += f" ({message})"
            logger.error(error)
            raise AssertionError(error)

    def assert_false(self, condition: bool, message: str = "") -> None:
        """Assert condition is false"""
        self.assertion_count += 1
        if condition:
            error = f"Assertion failed: condition is not false"
            if message:
                error += f" ({message})"
            logger.error(error)
            raise AssertionError(error)

    def assert_not_none(self, value: Any, message: str = "") -> None:
        """Assert value is not None"""
        self.assertion_count += 1
        if value is None:
            error = f"Assertion failed: value is None"
            if message:
                error += f" ({message})"
            logger.error(error)
            raise AssertionError(error)

    def assert_in(self, item: Any, container: Any, message: str = "") -> None:
        """Assert item is in container"""
        self.assertion_count += 1
        if item not in container:
            error = f"Assertion failed: {item} not in {container}"
            if message:
                error += f" ({message})"
            logger.error(error)
            raise AssertionError(error)

    def assert_raises(self, exception_type: type, func: Callable, *args, **kwargs) -> None:
        """Assert that function raises exception"""
        self.assertion_count += 1
        try:
            func(*args, **kwargs)
            error = f"Assertion failed: {exception_type.__name__} not raised"
            logger.error(error)
            raise AssertionError(error)
        except exception_type:
            # Expected
            pass


class MockObject(ABC):
    """
    Base class for mock objects
    Used to isolate units in tests
    """

    def __init__(self):
        self.call_count = 0
        self.call_args_list: List[tuple] = []
        self.return_value: Optional[Any] = None

    def __call__(self, *args, **kwargs) -> Any:
        """Record call"""
        self.call_count += 1
        self.call_args_list.append((args, kwargs))
        return self.return_value

    def assert_called(self) -> None:
        """Assert mock was called at least once"""
        if self.call_count == 0:
            raise AssertionError("Mock was not called")

    def assert_called_with(self, *args, **kwargs) -> None:
        """Assert mock was called with specific arguments"""
        if not self.call_args_list:
            raise AssertionError("Mock was not called")

        last_call = self.call_args_list[-1]
        if last_call != (args, kwargs):
            raise AssertionError(
                f"Expected call with {(args, kwargs)}, "
                f"got {last_call}"
            )

    def assert_call_count(self, count: int) -> None:
        """Assert mock was called specific number of times"""
        if self.call_count != count:
            raise AssertionError(
                f"Expected {count} calls, got {self.call_count}"
            )

    def reset(self) -> None:
        """Reset mock state"""
        self.call_count = 0
        self.call_args_list = []


class TestSuite:
    """
    Collection of test cases
    Manages execution and reporting
    """

    def __init__(self, name: str = "Test Suite"):
        self.name = name
        self.tests: List[TestCase] = []
        self.metrics: List[TestMetrics] = []
        self.passed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.error_count = 0

    def add_test(self, test_case: TestCase) -> None:
        """Add test case to suite"""
        self.tests.append(test_case)
        logger.debug(f"Added test: {test_case.name}")

    async def run(self, filter_tags: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run all tests in suite
        Optionally filter by tags
        """
        logger.info(f"Running test suite: {self.name}")
        self.metrics = []
        self.passed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.error_count = 0

        for test in self.tests:
            # Filter by tags if specified
            if filter_tags and not any(tag in test.tags for tag in filter_tags):
                continue

            # Skip if reason provided
            if test.skip_reason:
                logger.info(f"Skipped: {test.name} ({test.skip_reason})")
                self.skipped_count += 1
                continue

            # Run test
            await self._run_test(test)

        return self.get_summary()

    async def _run_test(self, test: TestCase) -> None:
        """Run single test"""
        start_time = time.time()
        assertions = AssertionHelper(test.name)

        try:
            # Setup
            if test.setup_func:
                await test.setup_func()

            # Execute
            logger.info(f"Running: {test.name}")
            await test.test_func(assertions)

            # Teardown
            if test.teardown_func:
                await test.teardown_func()

            # Record success
            duration_ms = (time.time() - start_time) * 1000
            metric = TestMetrics(
                test_name=test.name,
                status=TestResultStatus.PASSED,
                duration_ms=duration_ms,
                assertions_count=assertions.assertion_count
            )
            self.metrics.append(metric)
            self.passed_count += 1
            logger.info(f"PASSED: {test.name} ({duration_ms:.2f}ms)")

        except AssertionError as e:
            duration_ms = (time.time() - start_time) * 1000
            metric = TestMetrics(
                test_name=test.name,
                status=TestResultStatus.FAILED,
                duration_ms=duration_ms,
                assertions_count=assertions.assertion_count,
                error_message=str(e)
            )
            self.metrics.append(metric)
            self.failed_count += 1
            logger.error(f"FAILED: {test.name} - {e}")

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            metric = TestMetrics(
                test_name=test.name,
                status=TestResultStatus.ERROR,
                duration_ms=duration_ms,
                assertions_count=assertions.assertion_count,
                error_message=str(e)
            )
            self.metrics.append(metric)
            self.error_count += 1
            logger.error(f"ERROR: {test.name} - {e}")

    def get_summary(self) -> Dict[str, Any]:
        """Get test execution summary"""
        total = self.passed_count + self.failed_count + self.error_count + self.skipped_count
        total_time = sum(m.duration_ms for m in self.metrics)

        return {
            'suite_name': self.name,
            'total_tests': total,
            'passed': self.passed_count,
            'failed': self.failed_count,
            'error': self.error_count,
            'skipped': self.skipped_count,
            'success_rate': (
                self.passed_count / total * 100 if total > 0 else 0
            ),
            'total_time_ms': total_time,
            'metrics': [m.to_dict() for m in self.metrics]
        }


def test_timeout(seconds: float) -> Callable:
    """Decorator to add timeout to test"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            import asyncio
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=seconds
                )
            except asyncio.TimeoutError:
                raise TimeoutError(f"Test exceeded {seconds}s timeout")
        return wrapper
    return decorator


def parametrize(parameter_name: str, values: List[Any]) -> Callable:
    """Decorator for parametrized tests"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for value in values:
                kwargs[parameter_name] = value
                await func(*args, **kwargs)
        return wrapper
    return decorator


class BenchmarkHelper:
    """
    Performance benchmarking utilities
    Measures execution time and resource usage
    """

    def __init__(self):
        self.benchmarks: List[Dict[str, Any]] = []

    def measure(self, operation_name: str, func: Callable, *args, **kwargs) -> float:
        """Measure operation execution time"""
        start_time = time.time()
        result = func(*args, **kwargs)
        duration_ms = (time.time() - start_time) * 1000

        self.benchmarks.append({
            'operation': operation_name,
            'duration_ms': duration_ms,
            'timestamp': datetime.utcnow().isoformat()
        })

        logger.info(f"Benchmark: {operation_name} - {duration_ms:.2f}ms")
        return duration_ms

    async def measure_async(self, operation_name: str, coro) -> float:
        """Measure async operation execution time"""
        start_time = time.time()
        await coro
        duration_ms = (time.time() - start_time) * 1000

        self.benchmarks.append({
            'operation': operation_name,
            'duration_ms': duration_ms,
            'timestamp': datetime.utcnow().isoformat()
        })

        logger.info(f"Benchmark: {operation_name} - {duration_ms:.2f}ms")
        return duration_ms

    def get_report(self) -> Dict[str, Any]:
        """Get benchmark report"""
        if not self.benchmarks:
            return {'total_benchmarks': 0}

        durations = [b['duration_ms'] for b in self.benchmarks]
        return {
            'total_benchmarks': len(self.benchmarks),
            'min_ms': min(durations),
            'max_ms': max(durations),
            'avg_ms': sum(durations) / len(durations),
            'benchmarks': self.benchmarks
        }


__all__ = [
    'TestResultStatus',
    'TestCase',
    'TestMetrics',
    'AssertionHelper',
    'MockObject',
    'TestSuite',
    'test_timeout',
    'parametrize',
    'BenchmarkHelper',
]
