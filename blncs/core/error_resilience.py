"""
BLNCS Enhanced Error Handling and Resilience System
Comprehensive error handling, recovery, and resilience management
"""

import time
import threading
import traceback
import functools
import logging
import asyncio
import json
import os
from typing import Dict, Any, Optional, Callable, List, Type, Union, Awaitable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(Enum):
    """Available recovery strategies"""
    RETRY = "retry"
    FALLBACK = "fallback"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    RESTART_COMPONENT = "restart_component"
    EMERGENCY_STOP = "emergency_stop"
    IGNORE = "ignore"


@dataclass
class ErrorContext:
    """Context information for error handling"""
    component: str
    operation: str
    error_type: str
    error_message: str
    severity: ErrorSeverity
    timestamp: float
    traceback_info: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    recovery_attempts: int = 0
    max_recovery_attempts: int = 3


@dataclass
class RecoveryAction:
    """Recovery action configuration"""
    strategy: RecoveryStrategy
    action_function: Optional[Callable] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    max_attempts: int = 3
    backoff_factor: float = 1.5
    timeout: float = 30.0


class ErrorResilience:
    """Enhanced error handling and resilience system"""

    def __init__(self, config=None):
        self.config = config or {}
        self.error_history = deque(maxlen=self.config.get('max_error_history', 1000))
        self.error_stats = defaultdict(int)
        self.recovery_strategies: Dict[str, RecoveryAction] = {}
        self.error_handlers: Dict[Type[Exception], Callable] = {}
        self.circuit_breakers: Dict[str, Dict] = {}
        self.health_checks: Dict[str, Callable] = {}
        self.alert_handlers: List[Callable] = []
        self._lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        self._metrics = {
            'total_errors': 0,
            'recovered_errors': 0,
            'failed_recoveries': 0,
            'circuit_breaker_trips': 0
        }
        self._error_persistence_enabled = self.config.get('persist_errors', True)
        self._error_log_path = self.config.get('error_log_path', 'logs/errors.json')

        # Default recovery strategies
        self._setup_default_strategies()

        # Load persisted error data
        if self._error_persistence_enabled:
            self._load_persisted_errors()

    def _setup_default_strategies(self):
        """Setup default recovery strategies"""

        # Retry strategy
        self.register_recovery_strategy(
            "default_retry",
            RecoveryAction(
                strategy=RecoveryStrategy.RETRY,
                max_attempts=3,
                backoff_factor=2.0
            )
        )

        # Graceful degradation
        self.register_recovery_strategy(
            "graceful_degradation",
            RecoveryAction(
                strategy=RecoveryStrategy.GRACEFUL_DEGRADATION,
                action_function=self._default_graceful_degradation
            )
        )

        # Fallback strategy
        self.register_recovery_strategy(
            "fallback",
            RecoveryAction(
                strategy=RecoveryStrategy.FALLBACK,
                action_function=self._default_fallback
            )
        )

    def register_recovery_strategy(self, name: str, action: RecoveryAction):
        """Register a recovery strategy"""
        with self._lock:
            self.recovery_strategies[name] = action

    def register_error_handler(self, exception_type: Type[Exception], handler: Callable):
        """Register a custom error handler for specific exception types"""
        with self._lock:
            self.error_handlers[exception_type] = handler

    def handle_error(self, error: Exception, context: ErrorContext) -> bool:
        """Handle an error with appropriate recovery strategy"""
        with self._lock:
            # Update metrics
            self._metrics['total_errors'] += 1

            # Record error
            self.error_history.append((context, time.time()))
            self.error_stats[context.error_type] += 1

            # Persist error if enabled
            if self._error_persistence_enabled:
                self._persist_error(context)

            # Log error with structured format
            self._log_structured_error(error, context)

            # Check circuit breaker
            if self._is_circuit_broken(context.component):
                self.logger.warning(f"Circuit breaker open for {context.component}")
                self._trigger_alerts(context, "circuit_breaker_open")
                return False

            # Try custom handler first
            error_type = type(error)
            if error_type in self.error_handlers:
                try:
                    result = self.error_handlers[error_type](error, context)
                    if result:
                        self._metrics['recovered_errors'] += 1
                    return result
                except Exception as handler_error:
                    self.logger.error(f"Error handler failed: {handler_error}")

            # Apply recovery strategy based on severity
            result = self._apply_recovery_strategy(error, context)

            if result:
                self._metrics['recovered_errors'] += 1
            else:
                self._metrics['failed_recoveries'] += 1
                self._trigger_alerts(context, "recovery_failed")

            return result

    def _apply_recovery_strategy(self, error: Exception, context: ErrorContext) -> bool:
        """Apply appropriate recovery strategy"""
        strategy_name = self._determine_strategy(context)

        if strategy_name not in self.recovery_strategies:
            strategy_name = "default_retry"

        strategy = self.recovery_strategies[strategy_name]

        try:
            if strategy.strategy == RecoveryStrategy.RETRY:
                return self._handle_retry(error, context, strategy)
            elif strategy.strategy == RecoveryStrategy.FALLBACK:
                return self._handle_fallback(error, context, strategy)
            elif strategy.strategy == RecoveryStrategy.GRACEFUL_DEGRADATION:
                return self._handle_graceful_degradation(error, context, strategy)
            elif strategy.strategy == RecoveryStrategy.IGNORE:
                self.logger.info(f"Ignoring error in {context.component}")
                return True
            else:
                return False

        except Exception as recovery_error:
            self.logger.error(f"Recovery strategy failed: {recovery_error}")
            return False

    def _determine_strategy(self, context: ErrorContext) -> str:
        """Determine best recovery strategy based on error context"""
        if context.severity == ErrorSeverity.CRITICAL:
            return "graceful_degradation"
        elif context.severity == ErrorSeverity.HIGH:
            return "fallback"
        elif context.recovery_attempts < 3:
            return "default_retry"
        else:
            return "graceful_degradation"

    def _handle_retry(self, error: Exception, context: ErrorContext, strategy: RecoveryAction) -> bool:
        """Handle retry strategy"""
        if context.recovery_attempts >= strategy.max_attempts:
            self.logger.warning(
                f"Maximum retry attempts ({strategy.max_attempts}) exceeded for "
                f"{context.component}.{context.operation}"
            )
            return False

        # Calculate backoff delay
        delay = strategy.backoff_factor ** context.recovery_attempts
        time.sleep(min(delay, 30))  # Cap at 30 seconds

        context.recovery_attempts += 1
        self.logger.info(
            f"Retrying {context.component}.{context.operation} "
            f"(attempt {context.recovery_attempts}/{strategy.max_attempts})"
        )

        return True

    def _handle_fallback(self, error: Exception, context: ErrorContext, strategy: RecoveryAction) -> bool:
        """Handle fallback strategy"""
        if strategy.action_function:
            try:
                result = strategy.action_function(error, context, **strategy.parameters)
                self.logger.info(f"Fallback successful for {context.component}.{context.operation}")
                return result
            except Exception as fallback_error:
                self.logger.error(f"Fallback failed: {fallback_error}")

        return False

    def _handle_graceful_degradation(self, error: Exception, context: ErrorContext, strategy: RecoveryAction) -> bool:
        """Handle graceful degradation strategy"""
        if strategy.action_function:
            try:
                result = strategy.action_function(error, context, **strategy.parameters)
                self.logger.info(f"Graceful degradation applied for {context.component}")
                return result
            except Exception as degradation_error:
                self.logger.error(f"Graceful degradation failed: {degradation_error}")

        # Default graceful degradation - continue with reduced functionality
        self.logger.warning(f"Operating with reduced functionality in {context.component}")
        return True

    def _default_fallback(self, error: Exception, context: ErrorContext, **kwargs) -> bool:
        """Default fallback implementation"""
        self.logger.info(f"Applying default fallback for {context.component}")
        return True

    def _default_graceful_degradation(self, error: Exception, context: ErrorContext, **kwargs) -> bool:
        """Default graceful degradation implementation"""
        self.logger.info(f"Applying graceful degradation for {context.component}")
        return True

    def _is_circuit_broken(self, component: str) -> bool:
        """Check if circuit breaker is open for component"""
        if component not in self.circuit_breakers:
            return False

        breaker = self.circuit_breakers[component]
        return breaker.get('open', False)

    def _update_circuit_breaker(self, component: str, success: bool):
        """Update circuit breaker state"""
        if component not in self.circuit_breakers:
            self.circuit_breakers[component] = {
                'failures': 0,
                'successes': 0,
                'last_failure': 0,
                'open': False
            }

        breaker = self.circuit_breakers[component]

        if success:
            breaker['successes'] += 1
            breaker['failures'] = max(0, breaker['failures'] - 1)

            # Close circuit if enough successes
            if breaker['successes'] >= 3:
                breaker['open'] = False
        else:
            breaker['failures'] += 1
            breaker['last_failure'] = time.time()

            # Open circuit if too many failures
            if breaker['failures'] >= 5:
                breaker['open'] = True
                self.logger.warning(f"Circuit breaker opened for {component}")

    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics and health metrics"""
        with self._lock:
            recent_errors = [
                (ctx, timestamp) for ctx, timestamp in self.error_history
                if time.time() - timestamp < 3600  # Last hour
            ]

            return {
                'total_errors': len(self.error_history),
                'recent_errors': len(recent_errors),
                'error_types': dict(self.error_stats),
                'circuit_breakers': {
                    comp: breaker for comp, breaker in self.circuit_breakers.items()
                    if breaker.get('failures', 0) > 0
                },
                'top_error_components': self._get_top_error_components(recent_errors)
            }

    def _get_top_error_components(self, recent_errors: List) -> Dict[str, int]:
        """Get components with most errors"""
        component_errors = defaultdict(int)
        for ctx, _ in recent_errors:
            component_errors[ctx.component] += 1

        return dict(sorted(component_errors.items(), key=lambda x: x[1], reverse=True)[:5])

    def reset_circuit_breaker(self, component: str):
        """Manually reset circuit breaker for a component"""
        with self._lock:
            if component in self.circuit_breakers:
                self.circuit_breakers[component] = {
                    'failures': 0,
                    'successes': 0,
                    'last_failure': 0,
                    'open': False
                }
                self.logger.info(f"Circuit breaker reset for {component}")

    def _log_structured_error(self, error: Exception, context: ErrorContext):
        """Log error with structured format"""
        error_data = {
            'timestamp': datetime.fromtimestamp(context.timestamp).isoformat(),
            'component': context.component,
            'operation': context.operation,
            'error_type': context.error_type,
            'error_message': context.error_message,
            'severity': context.severity.value,
            'recovery_attempts': context.recovery_attempts,
            'traceback': context.traceback_info,
            'metadata': context.metadata
        }

        # Log to standard logger
        self.logger.error(f"Error in {context.component}.{context.operation}: "
                         f"{context.error_message} (Severity: {context.severity.value})")

        # Log structured data if configured
        if self.config.get('structured_logging', False):
            self.logger.info(f"ERROR_STRUCTURED: {json.dumps(error_data)}")

    def _persist_error(self, context: ErrorContext):
        """Persist error to file for analysis"""
        try:
            error_data = {
                'timestamp': datetime.fromtimestamp(context.timestamp).isoformat(),
                **asdict(context)
            }

            # Ensure log directory exists
            log_path = Path(self._error_log_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Append to log file
            with open(log_path, 'a') as f:
                f.write(json.dumps(error_data) + '\n')

        except Exception as e:
            self.logger.warning(f"Failed to persist error: {e}")

    def _load_persisted_errors(self):
        """Load persisted errors for analysis"""
        try:
            log_path = Path(self._error_log_path)
            if not log_path.exists():
                return

            # Load recent errors (last 24 hours)
            cutoff_time = datetime.now() - timedelta(hours=24)

            with open(log_path, 'r') as f:
                for line in f:
                    try:
                        error_data = json.loads(line.strip())
                        error_time = datetime.fromisoformat(error_data['timestamp'])

                        if error_time > cutoff_time:
                            self.error_stats[error_data['error_type']] += 1

                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue

        except Exception as e:
            self.logger.warning(f"Failed to load persisted errors: {e}")

    def _trigger_alerts(self, context: ErrorContext, alert_type: str):
        """Trigger alerts for critical errors"""
        alert_data = {
            'type': alert_type,
            'timestamp': datetime.fromtimestamp(context.timestamp).isoformat(),
            'component': context.component,
            'operation': context.operation,
            'severity': context.severity.value,
            'error_message': context.error_message
        }

        # Call all registered alert handlers
        for handler in self.alert_handlers:
            try:
                handler(alert_data)
            except Exception as e:
                self.logger.error(f"Alert handler failed: {e}")

    def add_alert_handler(self, handler: Callable):
        """Add an alert handler"""
        self.alert_handlers.append(handler)

    def add_health_check(self, name: str, check_function: Callable):
        """Add a health check function"""
        self.health_checks[name] = check_function

    async def run_health_checks(self) -> Dict[str, Any]:
        """Run all registered health checks"""
        results = {}

        for name, check_func in self.health_checks.items():
            try:
                if asyncio.iscoroutinefunction(check_func):
                    result = await check_func()
                else:
                    result = check_func()

                results[name] = {
                    'status': 'healthy' if result else 'unhealthy',
                    'result': result,
                    'timestamp': datetime.now().isoformat()
                }

            except Exception as e:
                results[name] = {
                    'status': 'error',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }

        return results

    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics"""
        with self._lock:
            recent_errors = [
                (ctx, timestamp) for ctx, timestamp in self.error_history
                if time.time() - timestamp < 3600  # Last hour
            ]

            # Calculate error rates
            error_rate_1h = len(recent_errors)
            error_rate_5m = len([
                (ctx, timestamp) for ctx, timestamp in self.error_history
                if time.time() - timestamp < 300
            ])

            # Circuit breaker status
            active_breakers = {
                comp: breaker for comp, breaker in self.circuit_breakers.items()
                if breaker.get('open', False)
            }

            return {
                **self._metrics,
                'error_rate_1h': error_rate_1h,
                'error_rate_5m': error_rate_5m,
                'active_circuit_breakers': len(active_breakers),
                'circuit_breaker_details': active_breakers,
                'error_types_distribution': dict(self.error_stats),
                'top_error_components': self._get_top_error_components(recent_errors),
                'recovery_success_rate': (
                    self._metrics['recovered_errors'] / max(1, self._metrics['total_errors'])
                ) * 100
            }

    def export_error_report(self, hours: int = 24) -> Dict[str, Any]:
        """Export comprehensive error report"""
        cutoff_time = time.time() - (hours * 3600)
        recent_errors = [
            (ctx, timestamp) for ctx, timestamp in self.error_history
            if timestamp >= cutoff_time
        ]

        # Group errors by component and type
        component_errors = defaultdict(lambda: defaultdict(int))
        severity_distribution = defaultdict(int)
        hourly_distribution = defaultdict(int)

        for ctx, timestamp in recent_errors:
            component_errors[ctx.component][ctx.error_type] += 1
            severity_distribution[ctx.severity.value] += 1

            # Hour bucket
            hour = int((time.time() - timestamp) // 3600)
            hourly_distribution[hour] += 1

        return {
            'report_period_hours': hours,
            'total_errors': len(recent_errors),
            'component_breakdown': dict(component_errors),
            'severity_distribution': dict(severity_distribution),
            'hourly_distribution': dict(hourly_distribution),
            'circuit_breaker_status': self.circuit_breakers,
            'metrics': self.get_metrics(),
            'generated_at': datetime.now().isoformat()
        }

    def cleanup_old_errors(self, max_age_days: int = 7):
        """Clean up old error logs"""
        try:
            cutoff_time = time.time() - (max_age_days * 24 * 3600)

            # Clean in-memory history
            self.error_history = deque([
                (ctx, timestamp) for ctx, timestamp in self.error_history
                if timestamp >= cutoff_time
            ], maxlen=self.error_history.maxlen)

            # Clean persisted logs
            if self._error_persistence_enabled:
                log_path = Path(self._error_log_path)
                if log_path.exists():
                    # Read and filter log file
                    temp_path = log_path.with_suffix('.tmp')
                    cutoff_date = datetime.fromtimestamp(cutoff_time)

                    with open(log_path, 'r') as infile, open(temp_path, 'w') as outfile:
                        for line in infile:
                            try:
                                error_data = json.loads(line.strip())
                                error_time = datetime.fromisoformat(error_data['timestamp'])

                                if error_time >= cutoff_date:
                                    outfile.write(line)

                            except (json.JSONDecodeError, KeyError, ValueError):
                                continue

                    # Replace original file
                    temp_path.replace(log_path)

            self.logger.info(f"Cleaned up errors older than {max_age_days} days")

        except Exception as e:
            self.logger.error(f"Failed to clean up old errors: {e}")

    def shutdown(self):
        """Shutdown error resilience system"""
        try:
            # Save final state if persistence is enabled
            if self._error_persistence_enabled:
                self._save_state()

            # Clear handlers and data
            self.alert_handlers.clear()
            self.health_checks.clear()
            self.error_handlers.clear()
            self.recovery_strategies.clear()

            self.logger.info("Error resilience system shutdown complete")

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

    def _save_state(self):
        """Save current state for recovery"""
        try:
            state_data = {
                'metrics': self._metrics,
                'circuit_breakers': self.circuit_breakers,
                'error_stats': dict(self.error_stats),
                'timestamp': datetime.now().isoformat()
            }

            state_path = Path(self._error_log_path).parent / 'resilience_state.json'
            with open(state_path, 'w') as f:
                json.dump(state_data, f, indent=2)

        except Exception as e:
            self.logger.warning(f"Failed to save state: {e}")


def resilient_operation(component: str, operation: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """Decorator for resilient operations"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            resilience = get_error_resilience()

            while True:
                try:
                    result = func(*args, **kwargs)
                    # Update circuit breaker on success
                    resilience._update_circuit_breaker(component, True)
                    return result

                except Exception as e:
                    context = ErrorContext(
                        component=component,
                        operation=operation,
                        error_type=type(e).__name__,
                        error_message=str(e),
                        severity=severity,
                        timestamp=time.time(),
                        traceback_info=traceback.format_exc()
                    )

                    # Update circuit breaker on failure
                    resilience._update_circuit_breaker(component, False)

                    # Handle error with recovery
                    should_retry = resilience.handle_error(e, context)

                    if not should_retry:
                        raise  # Re-raise if recovery not possible

                    # Continue loop for retry

        return wrapper
    return decorator


def safe_operation(default_return=None, log_errors=True):
    """Decorator for safe operations that shouldn't crash the system"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_errors:
                    logging.error(f"Safe operation {func.__name__} failed: {e}")
                return default_return
        return wrapper
    return decorator


# Global instance management
_error_resilience = None
_resilience_lock = threading.Lock()


def get_error_resilience() -> ErrorResilience:
    """Get global error resilience system"""
    global _error_resilience
    if _error_resilience is None:
        with _resilience_lock:
            if _error_resilience is None:
                _error_resilience = ErrorResilience()
    return _error_resilience


__all__ = [
    'ErrorSeverity',
    'RecoveryStrategy',
    'ErrorContext',
    'RecoveryAction',
    'ErrorResilience',
    'resilient_operation',
    'safe_operation',
    'get_error_resilience'
]