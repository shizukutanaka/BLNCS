"""
Health monitoring manager for BLNCS
Orchestrates health checks and provides unified health monitoring.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Callable
from collections import deque
import json

from .base import (
    HealthCheck, HealthCheckResult, HealthSummary, HealthStatus, 
    CheckCategory, HealthConfig
)
from .checks import (
    SystemResourceCheck, DatabaseHealthCheck, LightningNodeCheck,
    NetworkConnectivityCheck, StorageHealthCheck, PerformanceCheck
)
from ..logger import get_logger
from ..error_handler import get_error_handler, ErrorContext
from ..async_database import get_async_db_manager
from ..async_metrics import get_metrics_collector


class HealthMonitoringManager:
    """Comprehensive health monitoring system"""
    
    def __init__(self, config: Optional[HealthConfig] = None):
        self.config = config or HealthConfig()
        self.logger = get_logger(__name__)
        self.error_handler = get_error_handler()
        
        # Health checks registry
        self.health_checks: Dict[str, HealthCheck] = {}
        self.check_categories: Dict[CheckCategory, List[str]] = {}
        
        # Results storage
        self.latest_results: Dict[str, HealthCheckResult] = {}
        self.results_history: deque = deque(maxlen=self.config.max_history)
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_task: Optional[asyncio.Task] = None
        self.last_check_time: Optional[datetime] = None
        
        # Notification system
        self.alert_callbacks: List[Callable] = []
        self.consecutive_failures: Dict[str, int] = {}
        
        # Performance tracking
        self.total_checks_performed = 0
        self.total_check_time = 0.0
        
        # Database and metrics
        self.db_manager = None
        self.metrics_collector = None
    
    async def initialize(self):
        """Initialize the health monitoring system"""
        try:
            # Get database and metrics
            self.db_manager = await get_async_db_manager()
            self.metrics_collector = await get_metrics_collector()
            
            # Register default health checks
            await self._register_default_checks()
            
            self.logger.info("Health monitoring manager initialized")
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="health_manager",
                    operation="initialize",
                    severity="critical"
                )
            )
            raise
    
    async def _register_default_checks(self):
        """Register default health checks"""
        
        # System resource check
        await self.register_check(SystemResourceCheck())
        
        # Database health check
        await self.register_check(DatabaseHealthCheck())
        
        # Network connectivity check
        await self.register_check(NetworkConnectivityCheck())
        
        # Storage health check
        await self.register_check(StorageHealthCheck())
        
        # Performance check
        await self.register_check(PerformanceCheck())
    
    async def register_check(self, health_check: HealthCheck):
        """Register a health check"""
        try:
            name = health_check.name
            category = health_check.category
            
            # Store the check
            self.health_checks[name] = health_check
            
            # Organize by category
            if category not in self.check_categories:
                self.check_categories[category] = []
            self.check_categories[category].append(name)
            
            self.logger.info(f"Registered health check: {name} ({category.value})")
            
        except Exception as e:
            self.logger.error(f"Failed to register health check {health_check.name}: {e}")
    
    async def register_lightning_check(self, client_factory: Callable):
        """Register Lightning node health check with client factory"""
        lightning_check = LightningNodeCheck(client_factory=client_factory)
        await self.register_check(lightning_check)
    
    async def unregister_check(self, name: str):
        """Unregister a health check"""
        if name in self.health_checks:
            check = self.health_checks[name]
            category = check.category
            
            # Remove from main registry
            del self.health_checks[name]
            
            # Remove from category
            if category in self.check_categories and name in self.check_categories[category]:
                self.check_categories[category].remove(name)
            
            # Clean up results
            if name in self.latest_results:
                del self.latest_results[name]
            
            if name in self.consecutive_failures:
                del self.consecutive_failures[name]
            
            self.logger.info(f"Unregistered health check: {name}")
    
    async def run_check(self, name: str) -> Optional[HealthCheckResult]:
        """Run a specific health check"""
        if name not in self.health_checks:
            self.logger.warning(f"Health check not found: {name}")
            return None
        
        check = self.health_checks[name]
        
        try:
            start_time = time.time()
            result = await check.check()
            check_duration = time.time() - start_time
            
            # Update statistics
            self.total_checks_performed += 1
            self.total_check_time += check_duration
            
            # Store result
            self.latest_results[name] = result
            self.results_history.append(result)
            
            # Update consecutive failure tracking
            if result.status == HealthStatus.CRITICAL:
                self.consecutive_failures[name] = self.consecutive_failures.get(name, 0) + 1
            else:
                self.consecutive_failures[name] = 0
            
            # Record metrics
            if self.metrics_collector:
                await self.metrics_collector.record_gauge(
                    "health_check_status",
                    1.0 if result.status == HealthStatus.HEALTHY else 0.0,
                    labels={"check_name": name, "category": result.category.value}
                )
                
                await self.metrics_collector.record_histogram(
                    "health_check_duration",
                    check_duration,
                    labels={"check_name": name}
                )
            
            # Store in database
            await self._store_result_to_db(result)
            
            # Check for alerts
            await self._check_for_alerts(result)
            
            return result
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="health_manager",
                    operation=f"run_check_{name}",
                    severity="medium"
                )
            )
            
            # Create error result
            error_result = HealthCheckResult(
                name=name,
                status=HealthStatus.CRITICAL,
                message=f"Health check execution failed: {e}",
                category=check.category
            )
            
            self.latest_results[name] = error_result
            return error_result
    
    async def run_all_checks(self, categories: Optional[Set[CheckCategory]] = None) -> HealthSummary:
        """Run all health checks or checks in specified categories"""
        start_time = time.time()
        
        # Determine which checks to run
        checks_to_run = []
        for name, check in self.health_checks.items():
            if categories is None or check.category in categories:
                if check.enabled:
                    checks_to_run.append(name)
        
        # Run checks
        if self.config.parallel_checks:
            # Run checks in parallel with concurrency limit
            semaphore = asyncio.Semaphore(self.config.max_concurrent_checks)
            
            async def run_limited_check(check_name):
                async with semaphore:
                    return await self.run_check(check_name)
            
            tasks = [run_limited_check(name) for name in checks_to_run]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Run checks sequentially
            results = []
            for name in checks_to_run:
                result = await self.run_check(name)
                results.append(result)
        
        # Filter out exceptions and None results
        valid_results = [r for r in results if isinstance(r, HealthCheckResult)]
        
        # Create summary
        summary = self._create_summary(valid_results)
        summary.summary_duration = time.time() - start_time
        
        self.last_check_time = datetime.now()
        
        return summary
    
    async def run_quick_check(self) -> HealthSummary:
        """Run essential checks only for quick health assessment"""
        essential_categories = {CheckCategory.SYSTEM, CheckCategory.DATABASE, CheckCategory.LIGHTNING}
        return await self.run_all_checks(categories=essential_categories)
    
    def _create_summary(self, results: List[HealthCheckResult]) -> HealthSummary:
        """Create health summary from results"""
        if not results:
            return HealthSummary(
                overall_status=HealthStatus.UNKNOWN,
                total_checks=0,
                healthy_checks=0,
                warning_checks=0,
                critical_checks=0,
                unknown_checks=0
            )
        
        # Count statuses
        status_counts = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.WARNING: 0,
            HealthStatus.CRITICAL: 0,
            HealthStatus.UNKNOWN: 0
        }
        
        for result in results:
            status_counts[result.status] += 1
        
        # Determine overall status
        if status_counts[HealthStatus.CRITICAL] > 0:
            overall_status = HealthStatus.CRITICAL
        elif status_counts[HealthStatus.WARNING] > 0:
            overall_status = HealthStatus.WARNING
        elif status_counts[HealthStatus.UNKNOWN] > 0:
            overall_status = HealthStatus.UNKNOWN
        else:
            overall_status = HealthStatus.HEALTHY
        
        return HealthSummary(
            overall_status=overall_status,
            total_checks=len(results),
            healthy_checks=status_counts[HealthStatus.HEALTHY],
            warning_checks=status_counts[HealthStatus.WARNING],
            critical_checks=status_counts[HealthStatus.CRITICAL],
            unknown_checks=status_counts[HealthStatus.UNKNOWN],
            check_results=results
        )
    
    async def _store_result_to_db(self, result: HealthCheckResult):
        """Store health check result to database"""
        if not self.db_manager:
            return
        
        try:
            await self.db_manager.insert('health_check_results', {
                'check_name': result.name,
                'status': result.status.value,
                'message': result.message,
                'category': result.category.value,
                'details': json.dumps(result.details),
                'check_duration': result.check_duration,
                'recovery_suggestions': json.dumps(result.recovery_suggestions),
                'timestamp': result.timestamp.isoformat()
            })
            
        except Exception as e:
            self.logger.warning(f"Failed to store health check result to database: {e}")
    
    async def _check_for_alerts(self, result: HealthCheckResult):
        """Check if result should trigger alerts"""
        if result.status != HealthStatus.CRITICAL:
            return
        
        check_name = result.name
        consecutive_count = self.consecutive_failures.get(check_name, 0)
        
        if consecutive_count >= self.config.critical_alert_threshold:
            await self._send_alert(result, consecutive_count)
    
    async def _send_alert(self, result: HealthCheckResult, consecutive_count: int):
        """Send health alert to registered callbacks"""
        if not self.config.notification_enabled:
            return
        
        alert_data = {
            'check_name': result.name,
            'status': result.status.value,
            'message': result.message,
            'consecutive_failures': consecutive_count,
            'timestamp': result.timestamp.isoformat(),
            'recovery_suggestions': result.recovery_suggestions
        }
        
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert_data)
                else:
                    callback(alert_data)
            except Exception as e:
                self.logger.error(f"Alert callback failed: {e}")
    
    def add_alert_callback(self, callback: Callable):
        """Add alert notification callback"""
        self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable):
        """Remove alert notification callback"""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    async def start_monitoring(self):
        """Start continuous health monitoring"""
        if self.monitoring_active:
            self.logger.warning("Health monitoring is already active")
            return
        
        self.monitoring_active = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        self.logger.info("Started health monitoring")
    
    async def stop_monitoring(self):
        """Stop continuous health monitoring"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Stopped health monitoring")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        try:
            while self.monitoring_active:
                try:
                    await self.run_all_checks()
                    await asyncio.sleep(self.config.check_interval)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Error in health monitoring loop: {e}")
                    await asyncio.sleep(min(self.config.check_interval, 60))
        
        except asyncio.CancelledError:
            pass
    
    def get_latest_results(self) -> Dict[str, HealthCheckResult]:
        """Get latest health check results"""
        return self.latest_results.copy()
    
    def get_check_history(self, check_name: str, limit: int = 100) -> List[HealthCheckResult]:
        """Get history for specific check"""
        history = [r for r in self.results_history if r.name == check_name]
        return list(reversed(history))[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get health monitoring statistics"""
        avg_check_time = (
            self.total_check_time / self.total_checks_performed 
            if self.total_checks_performed > 0 else 0
        )
        
        return {
            'total_checks_performed': self.total_checks_performed,
            'total_check_time': self.total_check_time,
            'average_check_time': avg_check_time,
            'registered_checks': len(self.health_checks),
            'monitoring_active': self.monitoring_active,
            'last_check_time': self.last_check_time.isoformat() if self.last_check_time else None,
            'results_history_size': len(self.results_history),
            'consecutive_failures': dict(self.consecutive_failures),
            'check_categories': {cat.value: len(checks) for cat, checks in self.check_categories.items()}
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        await self.stop_monitoring()
        
        # Clear data structures
        self.health_checks.clear()
        self.latest_results.clear()
        self.results_history.clear()
        self.consecutive_failures.clear()
        self.alert_callbacks.clear()


# Global health manager instance
_global_health_manager: Optional[HealthMonitoringManager] = None


async def get_health_manager() -> HealthMonitoringManager:
    """Get global health monitoring manager"""
    global _global_health_manager
    if _global_health_manager is None:
        _global_health_manager = HealthMonitoringManager()
        await _global_health_manager.initialize()
    return _global_health_manager


# Convenience functions
async def run_health_check(check_name: str) -> Optional[HealthCheckResult]:
    """Convenience function to run single health check"""
    manager = await get_health_manager()
    return await manager.run_check(check_name)


async def run_all_health_checks() -> HealthSummary:
    """Convenience function to run all health checks"""
    manager = await get_health_manager()
    return await manager.run_all_checks()


async def get_health_summary() -> HealthSummary:
    """Convenience function to get health summary"""
    return await run_all_health_checks()


__all__ = [
    'HealthMonitoringManager',
    'get_health_manager',
    'run_health_check',
    'run_all_health_checks',
    'get_health_summary'
]