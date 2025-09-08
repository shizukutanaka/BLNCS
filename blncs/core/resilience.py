"""
System resilience and stability improvements for BLNCS
Automatic recovery, failover, and stability enhancements.
"""

import time
import threading
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import asyncio

from .logger import get_logger
from .config import get_config
from .exceptions import BLNCSError, CircuitBreaker, handle_exceptions
from .fast_cache import get_fast_cache


class SystemHealth(Enum):
    """System health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNSTABLE = "unstable"
    CRITICAL = "critical"
    DOWN = "down"


@dataclass
class HealthCheckResult:
    """Result of a health check"""
    component: str
    status: SystemHealth
    response_time_ms: float
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FailureRecord:
    """Record of system failure"""
    component: str
    failure_type: str
    timestamp: datetime
    error_message: str
    recovery_attempted: bool = False
    recovery_successful: bool = False
    recovery_time_ms: Optional[float] = None


class AutoRecovery:
    """Automatic system recovery mechanisms"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.cache = get_fast_cache()
        
        # Recovery configuration
        self.enabled = self.config.get('resilience.auto_recovery', True)
        self.max_recovery_attempts = self.config.get('resilience.max_recovery_attempts', 3)
        self.recovery_delay_base = self.config.get('resilience.recovery_delay_base', 1.0)
        self.recovery_delay_max = self.config.get('resilience.recovery_delay_max', 30.0)
        
        # State tracking
        self.failure_history = deque(maxlen=1000)
        self.recovery_attempts = {}
        self.circuit_breakers = {}
        self.recovery_lock = threading.Lock()
    
    def register_component(self, component: str, recovery_func: Callable) -> None:
        """Register a component for automatic recovery"""
        if component not in self.circuit_breakers:
            self.circuit_breakers[component] = CircuitBreaker(
                failure_threshold=3,
                timeout=60
            )
        
        self.recovery_attempts[component] = {
            'function': recovery_func,
            'attempts': 0,
            'last_attempt': None,
            'consecutive_failures': 0
        }
        
        self.logger.info(f"Registered component for auto-recovery: {component}")
    
    def record_failure(self, component: str, failure_type: str, error_message: str) -> None:
        """Record a component failure"""
        failure = FailureRecord(
            component=component,
            failure_type=failure_type,
            timestamp=datetime.now(),
            error_message=error_message
        )
        
        self.failure_history.append(failure)
        
        if component in self.recovery_attempts:
            self.recovery_attempts[component]['consecutive_failures'] += 1
        
        self.logger.warning(f"Failure recorded for {component}: {failure_type}")
        
        # Trigger recovery if enabled
        if self.enabled and component in self.recovery_attempts:
            threading.Thread(
                target=self._attempt_recovery,
                args=(component, failure),
                daemon=True
            ).start()
    
    def _attempt_recovery(self, component: str, failure: FailureRecord) -> None:
        """Attempt to recover a failed component"""
        with self.recovery_lock:
            recovery_info = self.recovery_attempts.get(component)
            if not recovery_info:
                return
            
            # Check if we've exceeded max attempts
            if recovery_info['attempts'] >= self.max_recovery_attempts:
                self.logger.error(f"Max recovery attempts exceeded for {component}")
                return
            
            # Calculate recovery delay with exponential backoff
            delay = min(
                self.recovery_delay_base * (2 ** recovery_info['attempts']),
                self.recovery_delay_max
            )
            
            self.logger.info(f"Attempting recovery for {component} in {delay}s")
            time.sleep(delay)
            
            # Attempt recovery
            start_time = time.time()
            recovery_successful = False
            
            try:
                recovery_info['function']()
                recovery_successful = True
                recovery_info['attempts'] = 0  # Reset on success
                recovery_info['consecutive_failures'] = 0
                
                # Reset circuit breaker
                if component in self.circuit_breakers:
                    self.circuit_breakers[component].reset()
                
                recovery_time = (time.time() - start_time) * 1000
                self.logger.info(f"Recovery successful for {component} in {recovery_time:.1f}ms")
                
                # Update failure record
                failure.recovery_attempted = True
                failure.recovery_successful = True
                failure.recovery_time_ms = recovery_time
                
            except Exception as e:
                recovery_info['attempts'] += 1
                recovery_info['last_attempt'] = datetime.now()
                
                self.logger.error(f"Recovery failed for {component}: {e}")
                failure.recovery_attempted = True
                failure.recovery_successful = False
                
                # Try again if we haven't exceeded max attempts
                if recovery_info['attempts'] < self.max_recovery_attempts:
                    threading.Thread(
                        target=self._attempt_recovery,
                        args=(component, failure),
                        daemon=True
                    ).start()
    
    def get_failure_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get failure statistics for specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_failures = [
            f for f in self.failure_history 
            if f.timestamp >= cutoff_time
        ]
        
        if not recent_failures:
            return {'total_failures': 0, 'period_hours': hours}
        
        # Group by component
        component_failures = {}
        recovery_stats = {'attempted': 0, 'successful': 0}
        
        for failure in recent_failures:
            comp = failure.component
            if comp not in component_failures:
                component_failures[comp] = {
                    'count': 0,
                    'types': {},
                    'recovery_attempted': 0,
                    'recovery_successful': 0
                }
            
            component_failures[comp]['count'] += 1
            failure_type = failure.failure_type
            component_failures[comp]['types'][failure_type] = \
                component_failures[comp]['types'].get(failure_type, 0) + 1
            
            if failure.recovery_attempted:
                component_failures[comp]['recovery_attempted'] += 1
                recovery_stats['attempted'] += 1
                
                if failure.recovery_successful:
                    component_failures[comp]['recovery_successful'] += 1
                    recovery_stats['successful'] += 1
        
        return {
            'period_hours': hours,
            'total_failures': len(recent_failures),
            'component_failures': component_failures,
            'recovery_stats': recovery_stats,
            'recovery_success_rate': (
                recovery_stats['successful'] / recovery_stats['attempted']
                if recovery_stats['attempted'] > 0 else 0
            )
        }


class HealthMonitor:
    """Advanced health monitoring system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # Health check configuration
        self.enabled = self.config.get('resilience.health_monitor', True)
        self.check_interval = self.config.get('resilience.health_check_interval', 30)
        self.component_timeouts = self.config.get('resilience.component_timeouts', {})
        
        # State tracking
        self.health_checks = {}
        self.health_history = deque(maxlen=500)
        self.current_health = {}
        self.alert_callbacks = []
        
        # Monitoring thread
        self._monitor_thread = None
        self._stop_monitoring = threading.Event()
        self._monitor_lock = threading.Lock()
    
    def register_health_check(self, component: str, check_func: Callable[[], bool],
                            timeout: float = 5.0, critical: bool = False) -> None:
        """Register a health check for a component"""
        self.health_checks[component] = {
            'function': check_func,
            'timeout': timeout,
            'critical': critical,
            'last_check': None,
            'consecutive_failures': 0
        }
        
        self.logger.info(f"Registered health check for {component}")
    
    def start_monitoring(self) -> None:
        """Start health monitoring"""
        if not self.enabled:
            self.logger.info("Health monitoring disabled")
            return
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        
        self._stop_monitoring.clear()
        self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitor_thread.start()
        self.logger.info("Health monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop health monitoring"""
        self._stop_monitoring.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        self.logger.info("Health monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main health monitoring loop"""
        while not self._stop_monitoring.is_set():
            try:
                self._perform_health_checks()
                self._update_system_health()
                self._stop_monitoring.wait(self.check_interval)
            except Exception as e:
                self.logger.error(f"Health monitoring error: {e}")
                self._stop_monitoring.wait(10)
    
    def _perform_health_checks(self) -> None:
        """Perform all registered health checks"""
        results = []
        
        for component, check_info in self.health_checks.items():
            result = self._check_component_health(component, check_info)
            results.append(result)
            
            with self._monitor_lock:
                self.current_health[component] = result
        
        # Store results in history
        self.health_history.extend(results)
    
    def _check_component_health(self, component: str, check_info: Dict) -> HealthCheckResult:
        """Perform health check for a single component"""
        start_time = time.time()
        
        try:
            # Execute health check with timeout
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Health check timeout for {component}")
            
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(check_info['timeout']))
            
            try:
                is_healthy = check_info['function']()
                signal.alarm(0)  # Cancel timeout
                
                response_time = (time.time() - start_time) * 1000
                
                if is_healthy:
                    check_info['consecutive_failures'] = 0
                    status = SystemHealth.HEALTHY
                    error_message = None
                else:
                    check_info['consecutive_failures'] += 1
                    status = SystemHealth.DEGRADED
                    error_message = "Health check returned False"
                
            except TimeoutError:
                signal.alarm(0)
                check_info['consecutive_failures'] += 1
                response_time = check_info['timeout'] * 1000
                status = SystemHealth.UNSTABLE
                error_message = f"Health check timeout ({check_info['timeout']}s)"
            
        except Exception as e:
            signal.alarm(0)
            check_info['consecutive_failures'] += 1
            response_time = (time.time() - start_time) * 1000
            status = SystemHealth.CRITICAL
            error_message = str(e)
        
        # Determine final status based on consecutive failures
        if check_info['consecutive_failures'] >= 3:
            status = SystemHealth.CRITICAL if check_info['critical'] else SystemHealth.UNSTABLE
        
        check_info['last_check'] = datetime.now()
        
        return HealthCheckResult(
            component=component,
            status=status,
            response_time_ms=response_time,
            error_message=error_message
        )
    
    def _update_system_health(self) -> None:
        """Update overall system health status"""
        if not self.current_health:
            return
        
        # Determine overall system health
        critical_components = 0
        unstable_components = 0
        degraded_components = 0
        total_components = len(self.current_health)
        
        for result in self.current_health.values():
            if result.status == SystemHealth.CRITICAL:
                critical_components += 1
            elif result.status == SystemHealth.UNSTABLE:
                unstable_components += 1
            elif result.status == SystemHealth.DEGRADED:
                degraded_components += 1
        
        # Calculate overall health
        if critical_components > 0:
            overall_health = SystemHealth.CRITICAL
        elif unstable_components > total_components * 0.3:  # More than 30% unstable
            overall_health = SystemHealth.UNSTABLE
        elif degraded_components > total_components * 0.5:  # More than 50% degraded
            overall_health = SystemHealth.DEGRADED
        else:
            overall_health = SystemHealth.HEALTHY
        
        # Trigger alerts if health deteriorated
        self._check_alerts(overall_health)
    
    def _check_alerts(self, current_health: SystemHealth) -> None:
        """Check if alerts should be triggered"""
        if current_health in [SystemHealth.CRITICAL, SystemHealth.UNSTABLE]:
            alert_data = {
                'type': 'health_degraded',
                'severity': current_health.value,
                'timestamp': datetime.now(),
                'components': self.current_health
            }
            
            for callback in self.alert_callbacks:
                try:
                    callback(alert_data)
                except Exception as e:
                    self.logger.error(f"Alert callback error: {e}")
    
    def add_alert_callback(self, callback: Callable[[Dict], None]) -> None:
        """Add callback for health alerts"""
        self.alert_callbacks.append(callback)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status"""
        with self._monitor_lock:
            return {
                'overall_health': self._calculate_overall_health(),
                'components': {
                    name: {
                        'status': result.status.value,
                        'response_time_ms': result.response_time_ms,
                        'error_message': result.error_message,
                        'last_check': result.timestamp.isoformat()
                    }
                    for name, result in self.current_health.items()
                },
                'monitoring_active': self._monitor_thread.is_alive() if self._monitor_thread else False
            }
    
    def _calculate_overall_health(self) -> str:
        """Calculate overall system health"""
        if not self.current_health:
            return SystemHealth.DOWN.value
        
        health_values = [result.status for result in self.current_health.values()]
        
        if SystemHealth.CRITICAL in health_values:
            return SystemHealth.CRITICAL.value
        elif SystemHealth.UNSTABLE in health_values:
            return SystemHealth.UNSTABLE.value
        elif SystemHealth.DEGRADED in health_values:
            return SystemHealth.DEGRADED.value
        else:
            return SystemHealth.HEALTHY.value


# Global instances
_auto_recovery = None
_health_monitor = None

def get_auto_recovery() -> AutoRecovery:
    """Get global auto-recovery instance"""
    global _auto_recovery
    if _auto_recovery is None:
        _auto_recovery = AutoRecovery()
    return _auto_recovery

def get_health_monitor() -> HealthMonitor:
    """Get global health monitor instance"""
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor()
    return _health_monitor