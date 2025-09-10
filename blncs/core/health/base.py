"""
Base health check components for BLNCS
Core data structures and interfaces for health monitoring.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Protocol
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod


class HealthStatus(Enum):
    """Health check status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    
    def __lt__(self, other):
        """Allow status comparison for severity ordering"""
        if not isinstance(other, HealthStatus):
            return NotImplemented
        
        order = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.WARNING: 1,
            HealthStatus.CRITICAL: 2,
            HealthStatus.UNKNOWN: 3
        }
        return order[self] < order[other]


class CheckCategory(Enum):
    """Categories of health checks"""
    SYSTEM = "system"
    NETWORK = "network"
    DATABASE = "database"
    LIGHTNING = "lightning"
    PERFORMANCE = "performance"
    SECURITY = "security"
    STORAGE = "storage"


@dataclass
class HealthCheckResult:
    """Result of a health check"""
    name: str
    status: HealthStatus
    message: str
    category: CheckCategory = CheckCategory.SYSTEM
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    check_duration: float = 0.0
    recovery_suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'name': self.name,
            'status': self.status.value,
            'message': self.message,
            'category': self.category.value,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
            'check_duration': self.check_duration,
            'recovery_suggestions': self.recovery_suggestions,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HealthCheckResult':
        """Create result from dictionary"""
        return cls(
            name=data['name'],
            status=HealthStatus(data['status']),
            message=data['message'],
            category=CheckCategory(data.get('category', 'system')),
            details=data.get('details', {}),
            timestamp=datetime.fromisoformat(data['timestamp']),
            check_duration=data.get('check_duration', 0.0),
            recovery_suggestions=data.get('recovery_suggestions', []),
            metadata=data.get('metadata', {})
        )


@dataclass
class HealthSummary:
    """Summary of all health checks"""
    overall_status: HealthStatus
    total_checks: int
    healthy_checks: int
    warning_checks: int
    critical_checks: int
    unknown_checks: int
    check_results: List[HealthCheckResult] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    summary_duration: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary"""
        return {
            'overall_status': self.overall_status.value,
            'total_checks': self.total_checks,
            'healthy_checks': self.healthy_checks,
            'warning_checks': self.warning_checks,
            'critical_checks': self.critical_checks,
            'unknown_checks': self.unknown_checks,
            'check_results': [result.to_dict() for result in self.check_results],
            'timestamp': self.timestamp.isoformat(),
            'summary_duration': self.summary_duration
        }


class HealthCheck(Protocol):
    """Protocol for health check implementations"""
    
    @property
    def name(self) -> str:
        """Name of the health check"""
        ...
    
    @property
    def category(self) -> CheckCategory:
        """Category of the health check"""
        ...
    
    async def check(self) -> HealthCheckResult:
        """Perform the health check"""
        ...
    
    @property
    def enabled(self) -> bool:
        """Whether the health check is enabled"""
        ...


class BaseHealthCheck(ABC):
    """Abstract base class for health checks"""
    
    def __init__(
        self,
        name: str,
        category: CheckCategory = CheckCategory.SYSTEM,
        enabled: bool = True,
        timeout: float = 30.0,
        retry_count: int = 1
    ):
        self._name = name
        self._category = category
        self._enabled = enabled
        self._timeout = timeout
        self._retry_count = retry_count
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def category(self) -> CheckCategory:
        return self._category
    
    @property
    def enabled(self) -> bool:
        return self._enabled
    
    def enable(self):
        """Enable the health check"""
        self._enabled = True
    
    def disable(self):
        """Disable the health check"""
        self._enabled = False
    
    @abstractmethod
    async def _perform_check(self) -> HealthCheckResult:
        """Perform the actual health check (to be implemented by subclasses)"""
        pass
    
    async def check(self) -> HealthCheckResult:
        """Perform health check with timeout and retry logic"""
        if not self._enabled:
            return HealthCheckResult(
                name=self._name,
                status=HealthStatus.UNKNOWN,
                message="Check disabled",
                category=self._category
            )
        
        start_time = time.time()
        last_error = None
        
        for attempt in range(self._retry_count):
            try:
                # Perform check with timeout
                import asyncio
                result = await asyncio.wait_for(
                    self._perform_check(),
                    timeout=self._timeout
                )
                result.check_duration = time.time() - start_time
                return result
                
            except asyncio.TimeoutError:
                last_error = f"Check timed out after {self._timeout} seconds"
            except Exception as e:
                last_error = str(e)
            
            if attempt < self._retry_count - 1:
                await asyncio.sleep(0.5)  # Brief delay between retries
        
        # All attempts failed
        return HealthCheckResult(
            name=self._name,
            status=HealthStatus.CRITICAL,
            message=f"Check failed: {last_error}",
            category=self._category,
            check_duration=time.time() - start_time
        )


class HealthThreshold:
    """Threshold configuration for health checks"""
    
    def __init__(
        self,
        warning_threshold: Optional[float] = None,
        critical_threshold: Optional[float] = None,
        invert: bool = False  # If True, lower values are worse
    ):
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self.invert = invert
    
    def evaluate(self, value: float) -> HealthStatus:
        """Evaluate value against thresholds"""
        if self.critical_threshold is not None:
            if self.invert:
                if value <= self.critical_threshold:
                    return HealthStatus.CRITICAL
            else:
                if value >= self.critical_threshold:
                    return HealthStatus.CRITICAL
        
        if self.warning_threshold is not None:
            if self.invert:
                if value <= self.warning_threshold:
                    return HealthStatus.WARNING
            else:
                if value >= self.warning_threshold:
                    return HealthStatus.WARNING
        
        return HealthStatus.HEALTHY


@dataclass
class HealthConfig:
    """Configuration for health monitoring"""
    check_interval: float = 60.0  # seconds
    max_history: int = 1000
    enable_auto_recovery: bool = True
    notification_enabled: bool = True
    critical_alert_threshold: int = 3  # consecutive critical results
    parallel_checks: bool = True
    max_concurrent_checks: int = 10
    default_timeout: float = 30.0
    default_retry_count: int = 1


__all__ = [
    'HealthStatus',
    'CheckCategory', 
    'HealthCheckResult',
    'HealthSummary',
    'HealthCheck',
    'BaseHealthCheck',
    'HealthThreshold',
    'HealthConfig'
]