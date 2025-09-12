"""
Enhanced BLNCS Error Recovery System
Automated error recovery and self-healing functionality with integrated monitoring.
"""

import time
import asyncio
from typing import Dict, Any, Optional, Callable, List, Union, Tuple
from threading import Lock, Thread, Event
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps

from .exceptions import BLNCSError, ConnectionError, TimeoutError, LightningError, ValidationError
from .config_manager import get_config_manager
from .logger import get_logger
from .cache_unified import get_cache
from .health import get_health_checker, HealthStatus
from .metrics import get_metrics_collector


class RecoveryStrategy(Enum):
    """Recovery strategy types"""
    IMMEDIATE = "immediate"
    GRADUAL = "gradual" 
    CIRCUIT_BREAKER = "circuit_breaker"
    HEALTH_CHECK = "health_check"
    BACKOFF = "backoff"
    RESET = "reset"


class RecoveryPriority(Enum):
    """Recovery priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class RecoveryAction:
    """Recovery action definition"""
    name: str
    strategy: RecoveryStrategy
    priority: RecoveryPriority
    action_func: Callable
    timeout: float = 30.0
    max_attempts: int = 3
    backoff_multiplier: float = 1.5
    prerequisites: List[str] = field(default_factory=list)
    health_checks: List[str] = field(default_factory=list)


@dataclass
class RecoveryResult:
    """Result of recovery attempt"""
    success: bool
    action_name: str
    attempts: int
    duration: float
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    health_status: Optional[HealthStatus] = None


class EnhancedErrorRecovery:
    """Enhanced error recovery system with health monitoring and metrics"""
    
    def __init__(self) -> None:
        self.config = get_config_manager()
        self.logger = get_logger(__name__)
        self.cache = get_cache()
        self.health_checker = get_health_checker()
        self.metrics = get_metrics_collector()
        
        # Recovery state tracking
        self.recovery_attempts = {}  # Retry attempts by error type
        self.recovery_lock = Lock()
        self.recovery_history = []  # History of recovery attempts
        self.active_recoveries = set()  # Currently active recovery operations
        self.shutdown_event = Event()
        
        # Recovery settings from enhanced config
        self.max_retries = self.config.get('recovery.max_retries', 3)
        self.retry_delay = self.config.get('recovery.retry_delay', 2.0)
        self.exponential_backoff = self.config.get('recovery.exponential_backoff', True)
        self.recovery_timeout = self.config.get('recovery.timeout', 300)
        self.health_check_enabled = self.config.get('recovery.health_check_enabled', True)
        self.proactive_recovery = self.config.get('recovery.proactive_recovery', True)
        
        # Initialize metrics
        self.recovery_counter = self.metrics.counter('recovery_attempts_total', 'Total recovery attempts')
        self.recovery_success_counter = self.metrics.counter('recovery_success_total', 'Successful recoveries')
        self.recovery_duration_histogram = self.metrics.histogram('recovery_duration_seconds', 'Recovery duration')
        
        # Recovery actions registry
        self.recovery_actions: Dict[str, RecoveryAction] = {}
        self._setup_default_recovery_actions()
        
        # Recovery strategies by error type
        self.recovery_strategies = {
            ConnectionError: ['connection_reset', 'connection_pool_refresh', 'network_check'],
            TimeoutError: ['timeout_adjustment', 'connection_optimization'],
            LightningError: ['lightning_cache_clear', 'lightning_reconnect'],
            ValidationError: ['input_sanitization', 'validation_reset'],
            BLNCSError: ['general_recovery', 'system_reset']
        }
        
        # Start proactive recovery if enabled
        if self.proactive_recovery:
            self._start_proactive_recovery()
    
    def _setup_default_recovery_actions(self):
        """Setup default recovery actions"""
        # Connection recovery actions
        self.register_recovery_action(RecoveryAction(
            name="connection_reset",
            strategy=RecoveryStrategy.IMMEDIATE,
            priority=RecoveryPriority.HIGH,
            action_func=self._reset_connections,
            timeout=10.0,
            health_checks=['network_connectivity']
        ))
        
        self.register_recovery_action(RecoveryAction(
            name="connection_pool_refresh",
            strategy=RecoveryStrategy.GRADUAL,
            priority=RecoveryPriority.MEDIUM,
            action_func=self._refresh_connection_pool,
            timeout=30.0
        ))
        
        self.register_recovery_action(RecoveryAction(
            name="network_check",
            strategy=RecoveryStrategy.HEALTH_CHECK,
            priority=RecoveryPriority.LOW,
            action_func=self._check_network_connectivity,
            timeout=15.0
        ))
        
        # Timeout recovery actions
        self.register_recovery_action(RecoveryAction(
            name="timeout_adjustment",
            strategy=RecoveryStrategy.GRADUAL,
            priority=RecoveryPriority.HIGH,
            action_func=self._adjust_timeouts,
            timeout=5.0
        ))
        
        # Lightning-specific actions
        self.register_recovery_action(RecoveryAction(
            name="lightning_cache_clear",
            strategy=RecoveryStrategy.IMMEDIATE,
            priority=RecoveryPriority.MEDIUM,
            action_func=self._clear_lightning_cache,
            timeout=5.0
        ))
        
        self.register_recovery_action(RecoveryAction(
            name="lightning_reconnect",
            strategy=RecoveryStrategy.CIRCUIT_BREAKER,
            priority=RecoveryPriority.HIGH,
            action_func=self._reconnect_lightning,
            timeout=20.0,
            health_checks=['lightning_node']
        ))
        
        # Validation recovery
        self.register_recovery_action(RecoveryAction(
            name="input_sanitization",
            strategy=RecoveryStrategy.IMMEDIATE,
            priority=RecoveryPriority.CRITICAL,
            action_func=self._sanitize_input,
            timeout=2.0
        ))
        
        # General recovery
        self.register_recovery_action(RecoveryAction(
            name="general_recovery",
            strategy=RecoveryStrategy.BACKOFF,
            priority=RecoveryPriority.MEDIUM,
            action_func=self._general_system_recovery,
            timeout=15.0
        ))
        
        self.register_recovery_action(RecoveryAction(
            name="system_reset",
            strategy=RecoveryStrategy.RESET,
            priority=RecoveryPriority.LOW,
            action_func=self._system_reset,
            timeout=60.0
        ))
    
    def register_recovery_action(self, action: RecoveryAction):
        """Register a recovery action"""
        self.recovery_actions[action.name] = action
        self.logger.debug(f"Registered recovery action: {action.name}")
    
    def attempt_recovery(self, error: Exception, operation: str, 
                        retry_func: Callable, *args, **kwargs) -> Any:
        """Attempt enhanced error recovery with monitoring"""
        error_key = f"{operation}:{error.__class__.__name__}"
        start_time = time.time()
        
        # Record recovery attempt
        self.recovery_counter.inc({'operation': operation, 'error_type': error.__class__.__name__})
        
        with self.recovery_lock:
            attempts = self.recovery_attempts.get(error_key, 0)
            
            if attempts >= self.max_retries:
                self.logger.error(f"Max retry attempts reached: {error_key}")
                self.metrics.counter('recovery_max_attempts_reached_total').inc()
                raise error
            
            # Increment attempt count
            self.recovery_attempts[error_key] = attempts + 1
            self.active_recoveries.add(error_key)
            
        self.logger.info(f"Attempting enhanced recovery ({attempts + 1}/{self.max_retries}): {error_key}")
        
        try:
            # Execute recovery actions based on error type
            recovery_results = self._execute_recovery_actions(error, operation)
            
            # Check if any recovery action succeeded
            if any(result.success for result in recovery_results):
                # Calculate and apply retry delay
                delay = self._calculate_retry_delay(attempts)
                if delay > 0:
                    time.sleep(delay)
                
                # Perform health check if enabled
                if self.health_check_enabled:
                    health_status = self.health_checker.check_system_health()
                    if health_status.status != HealthStatus.HEALTHY:
                        self.logger.warning(f"System health check failed during recovery: {health_status.message}")
                
                # Retry the original operation
                try:
                    result = retry_func(*args, **kwargs)
                    
                    # Success - update metrics and reset state
                    duration = time.time() - start_time
                    self.recovery_duration_histogram.observe(duration)
                    self.recovery_success_counter.inc({'operation': operation})
                    
                    with self.recovery_lock:
                        self.recovery_attempts.pop(error_key, None)
                        self.active_recoveries.discard(error_key)
                    
                    # Record successful recovery
                    recovery_record = {
                        'timestamp': datetime.now(),
                        'operation': operation,
                        'error_type': error.__class__.__name__,
                        'attempts': attempts + 1,
                        'duration': duration,
                        'success': True
                    }
                    self.recovery_history.append(recovery_record)
                    
                    self.logger.info(f"Enhanced error recovery successful: {error_key} (duration: {duration:.2f}s)")
                    return result
                    
                except Exception as retry_error:
                    self.logger.warning(f"Retry failed after recovery: {retry_error}")
                    raise retry_error
            else:
                self.logger.warning(f"All recovery actions failed for: {error_key}")
                raise error
                
        except Exception as recovery_error:
            duration = time.time() - start_time
            
            # Record failed recovery
            recovery_record = {
                'timestamp': datetime.now(),
                'operation': operation,
                'error_type': error.__class__.__name__,
                'attempts': attempts + 1,
                'duration': duration,
                'success': False,
                'error_message': str(recovery_error)
            }
            self.recovery_history.append(recovery_record)
            
            with self.recovery_lock:
                self.active_recoveries.discard(error_key)
            
            self.logger.error(f"Enhanced recovery failed: {recovery_error}")
            raise error
    
    def _execute_recovery_actions(self, error: Exception, operation: str) -> List[RecoveryResult]:
        """Execute recovery actions based on error type"""
        error_type = type(error)
        action_names = self.recovery_strategies.get(error_type, ['general_recovery'])
        
        results = []
        
        # Sort actions by priority
        actions = [self.recovery_actions[name] for name in action_names if name in self.recovery_actions]
        actions.sort(key=lambda x: x.priority.value)
        
        for action in actions:
            if self.shutdown_event.is_set():
                break
                
            result = self._execute_single_recovery_action(action, error, operation)
            results.append(result)
            
            # If this is a critical action and it succeeded, we might stop here
            if result.success and action.priority == RecoveryPriority.CRITICAL:
                break
        
        return results
    
    def _execute_single_recovery_action(self, action: RecoveryAction, 
                                       error: Exception, operation: str) -> RecoveryResult:
        """Execute a single recovery action with timeout and metrics"""
        start_time = time.time()
        
        self.logger.debug(f"Executing recovery action: {action.name}")
        
        try:
            # Check prerequisites
            if action.prerequisites and not self._check_prerequisites(action.prerequisites):
                return RecoveryResult(
                    success=False,
                    action_name=action.name,
                    attempts=1,
                    duration=0.0,
                    error_message="Prerequisites not met"
                )
            
            # Execute action with timeout
            result = self._run_with_timeout(action.action_func, action.timeout, error, operation)
            
            duration = time.time() - start_time
            
            # Perform health checks if specified
            health_status = None
            if action.health_checks:
                health_status = self._check_action_health(action.health_checks)
            
            return RecoveryResult(
                success=bool(result),
                action_name=action.name,
                attempts=1,
                duration=duration,
                health_status=health_status,
                metrics={'execution_time': duration}
            )
            
        except Exception as e:
            duration = time.time() - start_time
            self.logger.warning(f"Recovery action {action.name} failed: {e}")
            
            return RecoveryResult(
                success=False,
                action_name=action.name,
                attempts=1,
                duration=duration,
                error_message=str(e)
            )
    
    def _run_with_timeout(self, func: Callable, timeout: float, *args) -> Any:
        """Run function with timeout"""
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Recovery action timed out after {timeout}s")
        
        # Set up timeout signal
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(int(timeout))
        
        try:
            result = func(*args)
            return result
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    
    def _check_prerequisites(self, prerequisites: List[str]) -> bool:
        """Check if prerequisites are met"""
        for prereq in prerequisites:
            # Implementation depends on specific prerequisites
            # For now, assume all are met
            pass
        return True
    
    def _check_action_health(self, health_checks: List[str]) -> Optional[HealthStatus]:
        """Perform health checks for an action"""
        if not self.health_checker:
            return None
        
        # Run specific health checks
        for check_name in health_checks:
            status = self.health_checker.run_check(check_name)
            if status and status.status != HealthStatus.HEALTHY:
                return status
        
        return None
    
    # Recovery action implementations
    def _reset_connections(self, error: Exception, operation: str) -> bool:
        """Reset network connections"""
        try:
            self.logger.info("Resetting network connections...")
            
            # Clear connection-related cache
            self.cache.clear_pattern("connection:*")
            
            # Reset connection pool if available
            from .connection_pool_unified import get_connection_pool
            pool = get_connection_pool()
            if hasattr(pool, 'reset'):
                pool.reset()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to reset connections: {e}")
            return False
    
    def _refresh_connection_pool(self, error: Exception, operation: str) -> bool:
        """Refresh connection pool"""
        try:
            self.logger.info("Refreshing connection pool...")
            
            from .connection_pool_unified import get_connection_pool
            pool = get_connection_pool()
            if hasattr(pool, 'refresh'):
                pool.refresh()
                return True
            
            return False
        except Exception as e:
            self.logger.error(f"Failed to refresh connection pool: {e}")
            return False
    
    def _check_network_connectivity(self, error: Exception, operation: str) -> bool:
        """Check network connectivity"""
        try:
            import socket
            
            host = self.config.get('lightning.host', 'localhost')
            port = self.config.get('lightning.port', 8080)
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                
            if result == 0:
                self.logger.info(f"Network connectivity verified: {host}:{port}")
                return True
            else:
                self.logger.warning(f"Network connectivity failed: {host}:{port}")
                return False
                
        except Exception as e:
            self.logger.error(f"Network connectivity check failed: {e}")
            return False
    
    def _adjust_timeouts(self, error: Exception, operation: str) -> bool:
        """Dynamically adjust timeout settings"""
        try:
            self.logger.info("Adjusting timeout settings...")
            
            # Increase timeouts gradually
            current_timeout = self.config.get('lightning.timeout', 15)
            new_timeout = min(current_timeout * 1.5, 60)  # Max 60 seconds
            
            self.config.set('lightning.timeout', new_timeout)
            self.logger.info(f"Timeout adjusted: {current_timeout}s → {new_timeout}s")
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to adjust timeouts: {e}")
            return False
    
    def _clear_lightning_cache(self, error: Exception, operation: str) -> bool:
        """Clear Lightning-related cache"""
        try:
            self.logger.info("Clearing Lightning cache...")
            
            # Clear Lightning-specific cache entries
            self.cache.clear_pattern("lightning:*")
            self.cache.clear_pattern("node_info:*")
            self.cache.clear_pattern("channel:*")
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to clear Lightning cache: {e}")
            return False
    
    def _reconnect_lightning(self, error: Exception, operation: str) -> bool:
        """Reconnect to Lightning node"""
        try:
            self.logger.info("Attempting Lightning node reconnection...")
            
            # This would involve reconnecting to the Lightning node
            # Implementation depends on the specific Lightning client being used
            # For now, return True to indicate attempt was made
            
            time.sleep(2)  # Simulate reconnection time
            return True
        except Exception as e:
            self.logger.error(f"Failed to reconnect to Lightning node: {e}")
            return False
    
    def _sanitize_input(self, error: Exception, operation: str) -> bool:
        """Sanitize input that caused validation error"""
        try:
            self.logger.info("Attempting input sanitization...")
            
            # This would involve sanitizing the input that caused the error
            # Implementation depends on the specific validation error
            return True
        except Exception as e:
            self.logger.error(f"Failed to sanitize input: {e}")
            return False
    
    def _general_system_recovery(self, error: Exception, operation: str) -> bool:
        """General system recovery actions"""
        try:
            self.logger.info("Performing general system recovery...")
            
            # Clear expired cache entries
            if hasattr(self.cache, 'cleanup_expired'):
                self.cache.cleanup_expired()
            
            # Reload configuration
            self.config.reload()
            
            # Brief pause for system stabilization
            time.sleep(1)
            
            return True
        except Exception as e:
            self.logger.error(f"General system recovery failed: {e}")
            return False
    
    def _system_reset(self, error: Exception, operation: str) -> bool:
        """System reset recovery action"""
        try:
            self.logger.warning("Performing system reset recovery...")
            
            # Clear all cache
            self.cache.clear()
            
            # Reset recovery state
            with self.recovery_lock:
                self.recovery_attempts.clear()
                self.active_recoveries.clear()
            
            # Reload configuration
            self.config.reload()
            
            return True
        except Exception as e:
            self.logger.error(f"System reset failed: {e}")
            return False
    
    def _calculate_retry_delay(self, attempt: int) -> float:
        """Calculate retry delay with exponential backoff"""
        if self.exponential_backoff:
            return self.retry_delay * (2 ** attempt)
        else:
            return self.retry_delay
    
    def _start_proactive_recovery(self):
        """Start proactive recovery monitoring"""
        def proactive_monitor():
            while not self.shutdown_event.is_set():
                try:
                    # Perform proactive health checks
                    if self.health_checker:
                        health_status = self.health_checker.check_system_health()
                        if health_status.status != HealthStatus.HEALTHY:
                            self.logger.warning(f"Proactive recovery triggered: {health_status.message}")
                            # Trigger appropriate recovery actions
                    
                    # Sleep for monitoring interval
                    self.shutdown_event.wait(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"Proactive recovery monitor error: {e}")
                    self.shutdown_event.wait(60)
        
        monitor_thread = Thread(target=proactive_monitor, daemon=True)
        monitor_thread.start()
        self.logger.info("Proactive recovery monitoring started")
    
    def reset_recovery_state(self, operation: Optional[str] = None) -> None:
        """Reset recovery state"""
        with self.recovery_lock:
            if operation:
                # Reset specific operation
                keys_to_remove = [k for k in self.recovery_attempts.keys() 
                                if k.startswith(operation + ":")]
                for key in keys_to_remove:
                    del self.recovery_attempts[key]
                    self.active_recoveries.discard(key)
                self.logger.info(f"Recovery state reset for operation: {operation}")
            else:
                # Reset all
                self.recovery_attempts.clear()
                self.active_recoveries.clear()
                self.logger.info("All recovery state reset")
    
    def get_recovery_status(self) -> Dict[str, Any]:
        """Get comprehensive recovery status"""
        with self.recovery_lock:
            return {
                'active_recoveries': list(self.active_recoveries),
                'recovery_attempts': dict(self.recovery_attempts),
                'max_retries': self.max_retries,
                'retry_delay': self.retry_delay,
                'exponential_backoff': self.exponential_backoff,
                'recovery_timeout': self.recovery_timeout,
                'health_check_enabled': self.health_check_enabled,
                'proactive_recovery': self.proactive_recovery,
                'registered_actions': list(self.recovery_actions.keys()),
                'recovery_history_count': len(self.recovery_history),
                'recent_recoveries': self.recovery_history[-10:] if self.recovery_history else []
            }
    
    def get_recovery_statistics(self) -> Dict[str, Any]:
        """Get recovery statistics"""
        if not self.recovery_history:
            return {'total_attempts': 0, 'success_rate': 0.0, 'average_duration': 0.0}
        
        total_attempts = len(self.recovery_history)
        successful_attempts = sum(1 for record in self.recovery_history if record['success'])
        success_rate = successful_attempts / total_attempts
        
        durations = [record['duration'] for record in self.recovery_history]
        average_duration = sum(durations) / len(durations) if durations else 0.0
        
        return {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'success_rate': success_rate,
            'average_duration': average_duration,
            'error_types': list(set(record['error_type'] for record in self.recovery_history)),
            'operations': list(set(record['operation'] for record in self.recovery_history))
        }
    
    def shutdown(self):
        """Shutdown recovery system"""
        self.logger.info("Shutting down enhanced recovery system...")
        self.shutdown_event.set()


class EnhancedAutoRecoveryDecorator:
    """Enhanced auto recovery decorator with monitoring"""
    
    def __init__(self, operation_name: str, max_retries: int = 3, 
                 recoverable_errors: tuple = None, health_check: bool = True):
        self.operation_name = operation_name
        self.max_retries = max_retries
        self.recoverable_errors = recoverable_errors or (
            BLNCSError, ConnectionError, TimeoutError, LightningError, ValidationError
        )
        self.health_check = health_check
        self.recovery_system = None
    
    def __call__(self, func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if self.recovery_system is None:
                self.recovery_system = get_enhanced_error_recovery()
            
            last_error = None
            
            for attempt in range(self.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except self.recoverable_errors as e:
                    last_error = e
                    if attempt < self.max_retries:
                        try:
                            return self.recovery_system.attempt_recovery(
                                e, self.operation_name, func, *args, **kwargs
                            )
                        except Exception:
                            # Recovery failed, continue to next attempt
                            continue
                    else:
                        # Max attempts reached
                        break
                except Exception as e:
                    # Non-recoverable error
                    raise e
            
            # All attempts failed
            if last_error:
                raise last_error
            
        return wrapper


# Global instance
_enhanced_recovery_system = None
_recovery_lock = Lock()

def get_enhanced_error_recovery() -> EnhancedErrorRecovery:
    """Get enhanced error recovery system (singleton)"""
    global _enhanced_recovery_system
    
    if _enhanced_recovery_system is None:
        with _recovery_lock:
            if _enhanced_recovery_system is None:
                _enhanced_recovery_system = EnhancedErrorRecovery()
    
    return _enhanced_recovery_system


# Convenience decorators
def enhanced_auto_recover(operation_name: str, max_retries: int = 3, 
                         recoverable_errors: tuple = None, health_check: bool = True):
    """Enhanced auto recovery decorator factory function"""
    return EnhancedAutoRecoveryDecorator(
        operation_name, max_retries, recoverable_errors, health_check
    )


def lightning_auto_recover(operation_name: str, max_retries: int = 3):
    """Auto recovery specifically for Lightning operations"""
    return enhanced_auto_recover(
        operation_name, 
        max_retries, 
        (LightningError, ConnectionError, TimeoutError),
        health_check=True
    )


def network_auto_recover(operation_name: str, max_retries: int = 5):
    """Auto recovery specifically for network operations"""
    return enhanced_auto_recover(
        operation_name,
        max_retries,
        (ConnectionError, TimeoutError),
        health_check=True
    )