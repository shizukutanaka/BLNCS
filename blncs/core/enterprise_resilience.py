"""Enterprise Resilience and Error Recovery System

Production-grade error handling with self-healing capabilities.
"""

import asyncio
import functools
import logging
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Type, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
import signal
import sys
from collections import deque


class FailureMode(Enum):
    """Types of system failures"""
    TRANSIENT = "transient"  # Temporary, retry may succeed
    PERMANENT = "permanent"  # Permanent failure, needs intervention
    DEGRADED = "degraded"  # Partial failure, system can continue with reduced functionality
    CASCADE = "cascade"  # Failure affecting multiple components
    CRITICAL = "critical"  # System-critical failure requiring immediate action


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: int = 60  # seconds
    half_open_max_calls: int = 3
    exceptions_to_track: List[Type[Exception]] = field(default_factory=lambda: [Exception])


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit tripped, rejecting calls
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """Advanced circuit breaker implementation"""

    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.half_open_calls = 0
        self._lock = threading.Lock()
        self.logger = logging.getLogger(self.__class__.__name__)

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        with self._lock:
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.half_open_calls = 0
                else:
                    raise Exception("Circuit breaker is OPEN")

            if self.state == CircuitBreakerState.HALF_OPEN:
                if self.half_open_calls >= self.config.half_open_max_calls:
                    self.state = CircuitBreakerState.CLOSED
                    self.failure_count = 0
                self.half_open_calls += 1

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            raise

    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        if self.last_failure_time:
            time_since_failure = time.time() - self.last_failure_time
            return time_since_failure >= self.config.recovery_timeout
        return False

    def _on_success(self):
        """Handle successful call"""
        with self._lock:
            if self.state == CircuitBreakerState.HALF_OPEN:
                if self.half_open_calls >= self.config.half_open_max_calls:
                    self.state = CircuitBreakerState.CLOSED
                    self.failure_count = 0
                    self.logger.info("Circuit breaker closed after successful recovery")

    def _on_failure(self, exception: Exception):
        """Handle failed call"""
        with self._lock:
            if not any(isinstance(exception, exc_type) for exc_type in self.config.exceptions_to_track):
                return

            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.state == CircuitBreakerState.HALF_OPEN:
                self.state = CircuitBreakerState.OPEN
                self.logger.warning("Circuit breaker reopened due to failure in half-open state")
            elif self.failure_count >= self.config.failure_threshold:
                self.state = CircuitBreakerState.OPEN
                self.logger.error(f"Circuit breaker opened after {self.failure_count} failures")

    def get_state(self) -> CircuitBreakerState:
        """Get current circuit breaker state"""
        return self.state


class RetryStrategy:
    """Intelligent retry strategy with exponential backoff"""

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic"""
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e

                if attempt < self.max_retries:
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    time.sleep(delay)
                    continue

                raise

        raise last_exception


@dataclass
class HealthCheck:
    """Health check configuration"""
    name: str
    check_function: Callable[[], bool]
    interval: int = 30  # seconds
    timeout: int = 5  # seconds
    critical: bool = False


class SelfHealingSystem:
    """Self-healing system with automatic recovery"""

    def __init__(self):
        self.health_checks: List[HealthCheck] = []
        self.recovery_actions: Dict[str, Callable] = {}
        self.failure_history: deque = deque(maxlen=1000)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._monitoring = False
        self._monitor_thread = None
        self._stop_event = threading.Event()

    def register_health_check(self, health_check: HealthCheck):
        """Register a health check"""
        self.health_checks.append(health_check)
        self.logger.info(f"Registered health check: {health_check.name}")

    def register_recovery_action(self, failure_type: str, action: Callable):
        """Register recovery action for specific failure type"""
        self.recovery_actions[failure_type] = action
        self.logger.info(f"Registered recovery action for: {failure_type}")

    def start_monitoring(self):
        """Start health monitoring"""
        if self._monitoring:
            return

        self._monitoring = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_health)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
        self.logger.info("Health monitoring started")

    def stop_monitoring(self):
        """Stop health monitoring"""
        if not self._monitoring:
            return

        self._monitoring = False
        self._stop_event.set()

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

        self.logger.info("Health monitoring stopped")

    def _monitor_health(self):
        """Monitor system health continuously"""
        while self._monitoring and not self._stop_event.is_set():
            for health_check in self.health_checks:
                try:
                    # Execute health check with timeout
                    result = self._execute_with_timeout(
                        health_check.check_function,
                        health_check.timeout
                    )

                    if not result:
                        self._handle_health_failure(health_check)

                except Exception as e:
                    self.logger.error(f"Health check {health_check.name} failed: {e}")
                    self._handle_health_failure(health_check)

            # Wait before next round of checks
            self._stop_event.wait(30)

    def _execute_with_timeout(self, func: Callable, timeout: int) -> Any:
        """Execute function with timeout"""
        result = [None]
        exception = [None]

        def target():
            try:
                result[0] = func()
            except Exception as e:
                exception[0] = e

        thread = threading.Thread(target=target)
        thread.daemon = True
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            raise TimeoutError(f"Function execution exceeded timeout of {timeout} seconds")

        if exception[0]:
            raise exception[0]

        return result[0]

    def _handle_health_failure(self, health_check: HealthCheck):
        """Handle health check failure"""
        failure_entry = {
            'timestamp': datetime.now(),
            'health_check': health_check.name,
            'critical': health_check.critical
        }
        self.failure_history.append(failure_entry)

        # Attempt recovery
        if health_check.name in self.recovery_actions:
            self.logger.info(f"Attempting recovery for {health_check.name}")
            try:
                self.recovery_actions[health_check.name]()
                self.logger.info(f"Recovery successful for {health_check.name}")
            except Exception as e:
                self.logger.error(f"Recovery failed for {health_check.name}: {e}")

                if health_check.critical:
                    self._escalate_critical_failure(health_check, e)

    def _escalate_critical_failure(self, health_check: HealthCheck, exception: Exception):
        """Escalate critical failures"""
        self.logger.critical(f"CRITICAL FAILURE in {health_check.name}: {exception}")

        # Implement escalation logic (alerts, notifications, etc.)
        # This could trigger pager duty, send emails, etc.


class ErrorCollector:
    """Centralized error collection and analysis"""

    def __init__(self, max_errors: int = 10000):
        self.errors: deque = deque(maxlen=max_errors)
        self.error_stats: Dict[str, int] = {}
        self._lock = threading.Lock()
        self.logger = logging.getLogger(self.__class__.__name__)

    def collect(self, error: Exception, context: Optional[Dict] = None):
        """Collect error information"""
        with self._lock:
            error_entry = {
                'timestamp': datetime.now(),
                'type': type(error).__name__,
                'message': str(error),
                'traceback': traceback.format_exc(),
                'context': context or {}
            }

            self.errors.append(error_entry)

            # Update statistics
            error_type = type(error).__name__
            self.error_stats[error_type] = self.error_stats.get(error_type, 0) + 1

    def get_error_summary(self) -> Dict[str, Any]:
        """Get error statistics summary"""
        with self._lock:
            return {
                'total_errors': len(self.errors),
                'error_types': dict(self.error_stats),
                'recent_errors': list(self.errors)[-10:] if self.errors else []
            }

    def analyze_patterns(self) -> List[Dict[str, Any]]:
        """Analyze error patterns for insights"""
        patterns = []

        with self._lock:
            # Find most common errors
            if self.error_stats:
                most_common = max(self.error_stats, key=self.error_stats.get)
                patterns.append({
                    'pattern': 'most_common_error',
                    'error_type': most_common,
                    'count': self.error_stats[most_common]
                })

            # Detect error spikes
            if len(self.errors) >= 10:
                recent_window = datetime.now() - timedelta(minutes=5)
                recent_errors = [e for e in self.errors if e['timestamp'] > recent_window]

                if len(recent_errors) > len(self.errors) * 0.5:
                    patterns.append({
                        'pattern': 'error_spike',
                        'recent_count': len(recent_errors),
                        'spike_detected': True
                    })

        return patterns


class EnterpriseResilienceManager:
    """Main resilience manager coordinating all components"""

    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.retry_strategy = RetryStrategy()
        self.self_healing = SelfHealingSystem()
        self.error_collector = ErrorCollector()
        self.logger = logging.getLogger(self.__class__.__name__)
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown")
        self.self_healing.stop_monitoring()

        # Save error statistics
        self._save_error_report()

        sys.exit(0)

    def _save_error_report(self):
        """Save error report before shutdown"""
        try:
            summary = self.error_collector.get_error_summary()
            patterns = self.error_collector.analyze_patterns()

            report = {
                'timestamp': datetime.now().isoformat(),
                'summary': summary,
                'patterns': patterns
            }

            # Save to file or database
            self.logger.info(f"Error report saved: {report}")
        except Exception as e:
            self.logger.error(f"Failed to save error report: {e}")

    def register_circuit_breaker(self, name: str, config: CircuitBreakerConfig):
        """Register a circuit breaker for a service"""
        self.circuit_breakers[name] = CircuitBreaker(config)
        self.logger.info(f"Registered circuit breaker: {name}")

    def with_resilience(self, service_name: str = "default"):
        """Decorator to add resilience to functions"""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    # Use circuit breaker if available
                    if service_name in self.circuit_breakers:
                        cb = self.circuit_breakers[service_name]
                        return cb.call(lambda: self.retry_strategy.execute(func, *args, **kwargs))
                    else:
                        return self.retry_strategy.execute(func, *args, **kwargs)

                except Exception as e:
                    # Collect error information
                    self.error_collector.collect(e, {'service': service_name, 'function': func.__name__})
                    raise

            return wrapper
        return decorator

    async def with_async_resilience(self, service_name: str = "default"):
        """Async decorator for resilience"""
        def decorator(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                try:
                    # Implement async resilience logic
                    return await func(*args, **kwargs)
                except Exception as e:
                    self.error_collector.collect(e, {'service': service_name, 'function': func.__name__})
                    raise

            return wrapper
        return decorator

    def start(self):
        """Start resilience systems"""
        self.self_healing.start_monitoring()
        self.logger.info("Enterprise resilience system started")

    def stop(self):
        """Stop resilience systems"""
        self.self_healing.stop_monitoring()
        self._save_error_report()
        self.logger.info("Enterprise resilience system stopped")

    def get_status(self) -> Dict[str, Any]:
        """Get resilience system status"""
        return {
            'circuit_breakers': {
                name: cb.get_state().value
                for name, cb in self.circuit_breakers.items()
            },
            'error_summary': self.error_collector.get_error_summary(),
            'error_patterns': self.error_collector.analyze_patterns(),
            'health_checks': len(self.self_healing.health_checks)
        }